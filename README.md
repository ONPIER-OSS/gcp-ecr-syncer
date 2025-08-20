# GCP ECR Syncer: Requirements and Setup Guide

## 📜 Overview

The **GCP ECR Syncer** is a service that securely and automatically refreshes
AWS ECR authentication tokens. It uses Workload Identity Federation to
authenticate from GCP (GKE or Cloud Run) to AWS without static credentials.

This document outlines the necessary infrastructure and configuration on both
AWS and GCP to run the syncer successfully.

## ☁️ AWS Requirements

The AWS setup involves creating OIDC identity providers to trust Google Cloud
and an IAM role that the GCP services can assume.

### 1. IAM OIDC Identity Providers

Workload Identity Federation requires an OIDC provider in AWS for each unique
issuer URL. Since GKE and Cloud Run use different issuers, **two providers are
required**:

* **GKE Provider**: Trusts a specific GKE cluster's OIDC issuer URL
    (e.g., `container.googleapis.com/v1/projects/...`).
* **Google Cloud Provider**: Trusts the generic Google Cloud issuer URL
    (`accounts.google.com`), which is used by services like Cloud Run.

### 2. IAM Role for Federation

A single IAM Role is created for the syncer. Its **Trust Relationship Policy**
is configured to allow identities from *both* OIDC providers to assume it.

* **For GKE**: The policy trusts a specific Kubernetes Service Account (KSA)
    from a specific namespace.
* **For Cloud Run**: The policy trusts one or more specific GCP Service
    Accounts, identified by their unique 21-digit numeric IDs.

### 3. IAM Policy for ECR Access

The IAM Role is granted permissions to perform actions on ECR. The attached
policy allows the following actions on all ECR resources (`*`):

* `ecr:GetAuthorizationToken`
* `ecr:BatchGetImage`
* `ecr:GetDownloadUrlForLayer`

## 🚀 GCP Requirements

The GCP setup involves creating service accounts and enabling the necessary
APIs for the syncer to function.

### 1. Service Accounts

* **GCP Service Account (for Cloud Run)**: A dedicated GCP SA is required for
    the syncer on Cloud Run. It needs permissions for Secrets and Artifact
    Registry. You will need its **unique 21-digit ID** for the AWS IAM Role.
* **Kubernetes Service Account (for GKE)**: A KSA is needed in your GKE
    cluster. This KSA is linked to a GCP SA using Workload Identity.

### 2. Enabled APIs

Ensure the following Google Cloud APIs are enabled in your project:

* **IAM API** (`iam.googleapis.com`): To manage service accounts.
* **Secret Manager API** (`secretmanager.googleapis.com`): To store the
    fetched ECR token.
* **Artifact Registry API** (`artifactregistry.googleapis.com`): To update
    the remote repository credentials.

## ⚙️ Application Configuration (Environment Variables)

The application uses environment variables for its configuration.

| Variable              | Description                                        | Example Value        |
| :-------------------- | :------------------------------------------------- | :------------------- |
| `DEBUG`               | Set to `True` for verbose logging.                 | `False`              |
| `AWS_REGION`          | The AWS region of your ECR repository.             | `us-east-1`          |
| `AWS_ROLE_ARN`        | The ARN of the IAM Role created in AWS.            | `arn:aws:iam::123456789012:role/gcp-ecr-token-refresher-role` |
| `AWS_ECR_USERNAME`    | Username for ECR auth; almost always `AWS`.        | `AWS`                |
| `GCP_PROJECT_ID`      | The ID of your Google Cloud project.               | `my-gcp-project-id`  |
| `GCP_LOCATION`        | The GCP region for your Secret and repo.           | `europe-west1`       |
| `GCP_SECRET_NAME`     | The name of the secret in Secret Manager.          | `ecr-login-password` |
| `GCP_REPOSITORY_NAME` | Name of the remote Artifact Registry repo.         | `my-ecr-remote-repo` |
| **For Cloud Run:** |                                                    |                      |
| `AWS_AUDIENCE`        | OIDC token audience. Must match AWS OIDC provider. | `sts.amazonaws.com`  |
| **For GKE:** |                                                    |                      |
| `AWS_OIDC_TOKEN_PATH` | Path to GKE OIDC token; detects GKE environment.   | `/var/run/secrets/sts.googleapis.com/service-account-token`     |

**Note:** When running on Cloud Run, **do not set** `AWS_OIDC_TOKEN_PATH`. The
application detects its absence and generates a token for the attached GCP
Service Account.
