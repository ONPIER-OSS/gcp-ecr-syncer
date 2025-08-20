import base64
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional, cast

import boto3
import google.oauth2.id_token
from botocore.exceptions import ClientError
from google.auth import exceptions
from google.auth.transport import requests as grequests
from google.cloud import artifactregistry_v1, secretmanager
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class AWSConfig(BaseModel):
    region: str
    role_arn: str
    oidc_token_path: Optional[str] = None
    audience: Optional[str] = None
    ecr_username: str


class GCPConfig(BaseModel):
    project_id: str
    location: str
    secret_name: str
    repository_name: str


class Config(BaseSettings):
    model_config = SettingsConfigDict(env_nested_delimiter="_", env_nested_max_split=1)

    debug: bool = False
    aws: AWSConfig
    gcp: GCPConfig


def setup_logging(cfg: Config):
    """Sets up logging configuration."""
    if cfg.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def _get_oidc_token(cfg: Config) -> str:
    """
    Retrieves the OIDC token based on the environment.

    - If `aws.oidc_token_path` is set and the file exists, it reads the token
      from the file (GKE Workload Identity).
    - Otherwise, it generates an OIDC token for the ambient GCP Service Account
      (Cloud Run, etc.), using `aws.audience` as the target audience.

    Returns:
        str: The OIDC token.
    """
    # GKE Workload Identity Method (File-based)
    if cfg.aws.oidc_token_path and os.path.exists(cfg.aws.oidc_token_path):
        logger.info(
            f"GKE environment detected. Reading token from {cfg.aws.oidc_token_path}"
        )
        try:
            with open(cfg.aws.oidc_token_path, "r") as f:
                return f.read()
        except FileNotFoundError:
            logger.error(
                f"Service account token file not found at {cfg.aws.oidc_token_path}."
            )
            raise
    # GCP Service Account Method (Cloud Run, etc.)
    else:
        logger.info("Cloud Run/GCP environment detected. Generating OIDC token.")
        if not cfg.aws.audience:
            raise ValueError(
                "AWS_AUDIENCE must be configured for the Cloud Run/GCP environment."
            )
        try:
            auth_req = grequests.Request()
            oidc_token = google.oauth2.id_token.fetch_id_token(
                auth_req, cfg.aws.audience
            )
            if not oidc_token:
                raise RuntimeError("Failed to fetch OIDC token: received None.")

            return oidc_token
        except exceptions.DefaultCredentialsError as e:
            logger.error(
                "Could not find default credentials. Ensure the service account is configured correctly."
            )
            raise e


def get_login_password(cfg: Config) -> bytes:
    """
    Retrieves an authorization token from AWS ECR by first assuming a role
    via GCP Workload Identity Federation (supports GKE and Cloud Run).
    """
    logger.info("Starting Workload Identity Federation flow to get ECR password")

    try:
        web_identity_token = _get_oidc_token(cfg)
        logger.debug("Successfully retrieved the web identity token.")
    except Exception as e:
        logger.error(f"Failed to get OIDC token: {e}", exc_info=True)
        raise

    sts_client = boto3.client("sts", region_name=cfg.aws.region)
    try:
        logger.info(f"Attempting to assume role: {cfg.aws.role_arn}")
        assumed_role_object = sts_client.assume_role_with_web_identity(
            RoleArn=cfg.aws.role_arn,
            RoleSessionName="ECRTokenRefreshSession",
            WebIdentityToken=web_identity_token,
        )
        logger.info("Successfully assumed AWS role.")
    except ClientError as err:
        logger.error(
            "Failed to assume AWS role. Error Message:\n%s",
            err.response["Error"]["Message"],
        )
        logger.error("Check IAM role trust relationship and Workload Identity setup.")
        raise

    # 3. Extract temporary credentials
    credentials = assumed_role_object["Credentials"]

    # 4. Create the ECR client with temporary credentials
    logger.info("Creating ECR client with temporary credentials.")
    ecr_client = boto3.client(
        "ecr",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=cfg.aws.region,
    )

    # 5. Get the ECR authorization token
    try:
        logger.info("Getting ECR authorization token.")
        response = ecr_client.get_authorization_token()
        token = response["authorizationData"][0]["authorizationToken"]
    except ClientError as err:
        logger.error(
            "Failed to get ECR authorization token. Error Message:\n%s",
            err.response["Error"]["Message"],
        )
        raise

    token_split = base64.b64decode(token).split(b":")
    if len(token_split) != 2:
        raise Exception("Invalid token format")

    login_password = token_split[1]
    logger.info("Successfully retrieved ECR login password")
    return login_password


def store_login_password(cfg: Config, login_password: bytes) -> Optional[str]:
    """
    Stores the ECR login password in Google Cloud Secrets Manager.
    """
    logger.info("Storing ECR login password in Secrets Manager")
    client = secretmanager.SecretManagerServiceClient()
    parent = f"projects/{cfg.gcp.project_id}/secrets/{cfg.gcp.secret_name}"

    try:
        response = client.add_secret_version(
            request={"parent": parent, "payload": {"data": login_password}}
        )

        logger.info(f"Added secret version: {response.name}")
        return response.name
    except Exception as e:
        logger.error(
            f"Failed to store ECR login password in Secrets Manager: {e}",
            exc_info=True,
        )
        return None


def update_remote_repository(cfg: Config, secret_version_name: str) -> bool:
    """
    Updates the Artifact Registry remote repository with the new ECR login password.
    """
    logger.info("Updating Artifact Registry remote repository")
    client = artifactregistry_v1.ArtifactRegistryClient()
    name = f"projects/{cfg.gcp.project_id}/locations/{cfg.gcp.location}/repositories/{cfg.gcp.repository_name}"

    remote_repository_config = artifactregistry_v1.RemoteRepositoryConfig(
        upstream_credentials=artifactregistry_v1.RemoteRepositoryConfig.UpstreamCredentials(
            username_password_credentials=artifactregistry_v1.RemoteRepositoryConfig.UpstreamCredentials.UsernamePasswordCredentials(
                username=cfg.aws.ecr_username,
                password_secret_version=secret_version_name,
            )
        )
    )

    repository = artifactregistry_v1.Repository(
        name=name,
        remote_repository_config=remote_repository_config,
    )
    update_mask = {"paths": ["remote_repository_config.upstream_credentials"]}

    try:
        response = client.update_repository(
            request={"repository": repository, "update_mask": update_mask}
        )

        logger.info(f"Updated repository: {response.name}")
        return True
    except Exception as e:
        logger.error(
            f"Failed to update Artifact Registry repository: {e}", exc_info=True
        )
        return False


def cleanup_old_secret_versions(cfg: Config, hours: int = 12) -> None:
    """
    Destroys secret versions older than a specified number of hours.
    """
    logger.info(f"Cleaning up secret versions older than {hours} hours")
    client = secretmanager.SecretManagerServiceClient()
    parent = f"projects/{cfg.gcp.project_id}/secrets/{cfg.gcp.secret_name}"
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours)

    try:
        to_be_destroyed = []
        for version in client.list_secret_versions(request={"parent": parent}):
            if version.state == secretmanager.SecretVersion.State.ENABLED:
                create_time = cast(datetime, version.create_time)
                if create_time < cutoff:
                    to_be_destroyed.append(version.name)
        if len(to_be_destroyed) > 0:
            logger.info(
                f"Found {len(to_be_destroyed)} secret version{'s' if len(to_be_destroyed) > 1 else ''} to destroy"
            )
        else:
            logger.info("Found no secret versions to destroy")
            return
        for version_name in to_be_destroyed:
            try:
                destroy_request = secretmanager.DestroySecretVersionRequest(
                    name=version_name
                )
                client.destroy_secret_version(request=destroy_request)
            except Exception as e:
                logger.error(
                    f"Failed to destroy secret version {version_name}: {e}",
                    exc_info=True,
                )
        if len(to_be_destroyed) > 0:
            logger.info(
                f"Destroyed {len(to_be_destroyed)} secret version{'s' if len(to_be_destroyed) > 1 else ''} successfully"
            )

    except Exception as e:
        logger.error(f"Failed to cleanup secret versions: {e}", exc_info=True)


def main(cfg: Config) -> bool:
    """
    Main function to orchestrate the process of getting an ECR login password,
    storing it in Secrets Manager, and updating the Artifact Registry remote repository.
    """
    try:
        login_password = get_login_password(cfg)
    except Exception as e:
        logger.error(f"Failed to get ECR login password: {e}")
        return False

    secret_version_name = store_login_password(cfg, login_password)
    if not secret_version_name:
        logger.error("Failed to store ECR login password. Exiting.")
        return False

    if not update_remote_repository(cfg, secret_version_name):
        logger.error("Failed to update remote repository. Exiting.")
        return False

    cleanup_old_secret_versions(cfg)
    return True


if __name__ == "__main__":
    cfg = Config()  # pyright: ignore [reportCallIssue]
    setup_logging(cfg)
    try:
        if not main(cfg):
            sys.exit(1)
        logger.info("Successfully refreshed ECR login password")
    except Exception as err:
        logger.error("Failed to refresh ECR login password: %s", err, exc_info=True)
        sys.exit(1)
