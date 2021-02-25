#!/bin/bash

suffix=""

function generate_random_string () {
  local valid_chars=abcdefghijklmnopqrstuvwxyz0123456789
  for i in {1..8} ; do
    suffix+="${valid_chars:RANDOM%${#valid_chars}:1}"
    done
}

generate_random_string

pool_id="pool-"$suffix
oidc_provider_id="oidc-"$suffix
aws_provider_id="aws-"$suffix

# Fill in.
project_id=""
project_number=""
aws_account_id=""
aws_role_name=""
service_account_email=""
sub=""; # client_id from service account key file

oidc_aud="//iam.googleapis.com/projects/$project_number/locations/global/workloadIdentityPools/$pool_id/providers/$oidc_provider_id"
aws_aud="//iam.googleapis.com/projects/$project_number/locations/global/workloadIdentityPools/$pool_id/providers/$aws_provider_id"

gcloud config set project $project_id

# Create the Workload Identity Pool.
gcloud beta iam workload-identity-pools create $pool_id \
    --location="global" \
    --description="Test pool" \
    --display-name="Test pool for Java"

# Create the OIDC Provider.
gcloud beta iam workload-identity-pools providers create-oidc $oidc_provider_id \
    --workload-identity-pool=$pool_id \
    --issuer-uri="https://accounts.google.com" \
    --location="global" \
    --attribute-mapping="google.subject=assertion.sub"

# Create the AWS Provider.
gcloud beta iam workload-identity-pools providers create-aws $aws_provider_id \
    --workload-identity-pool=$pool_id \
    --account-id=$aws_account_id \
    --location="global"

# Give permission to impersonate the service account.
gcloud iam service-accounts add-iam-policy-binding $service_account_email \
--role roles/iam.workloadIdentityUser \
--member "principal://iam.googleapis.com/projects/$project_number/locations/global/workloadIdentityPools/$pool_id/subject/$sub"

gcloud iam service-accounts add-iam-policy-binding $service_account_email \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/$project_number/locations/global/workloadIdentityPools/$pool_id/attribute.aws_role/arn:aws:sts::$aws_account_id:assumed-role/$aws_role_name"

echo "OIDC audience:"$oidc_aud
echo "AWS audience:"$aws_aud
