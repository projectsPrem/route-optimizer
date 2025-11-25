#!/usr/bin/env python3
import os
import json
import boto3
from botocore.exceptions import ClientError

REGION = os.getenv("AWS_REGION", "us-east-1")
FRONTEND_BUCKET = os.getenv("FRONTEND_BUCKET", "route-optimization-frontend")
ARTIFACT_BUCKET = os.getenv("ARTIFACT_S3_BUCKET", FRONTEND_BUCKET)

s3 = boto3.client("s3", region_name=REGION)


def create_bucket(bucket_name):
    print(f"   ⏳ Creating/validating bucket: {bucket_name}")

    # -----------------------------
    # Create bucket (region-aware)
    # -----------------------------
    try:
        if REGION == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": REGION},
            )
        print(f"   ✔ Created bucket: {bucket_name}")

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            print(f"   ✔ Bucket exists: {bucket_name}")
        else:
            print(f"   ✖ Failed to create bucket {bucket_name}: {e}")
            return

    # -----------------------------
    # Attempt: Disable public-block
    # -----------------------------
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        print(f"   ✔ PublicAccessBlock updated for {bucket_name}")
    except Exception as e:
        print(f"   ⚠ Cannot update PublicAccessBlock (likely restricted): {e}")

    # -----------------------------
    # Attempt: Set bucket policy
    # -----------------------------
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }
        ],
    }

    try:
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(public_policy))
        print(f"   ✔ Public read policy applied for {bucket_name}")
    except Exception as e:
        print(f"   ⚠ Could not apply bucket policy (not fatal): {e}")

    # -----------------------------
    # Attempt: Enable website hosting
    # -----------------------------
    try:
        s3.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
                "ErrorDocument": {"Key": "index.html"},
            },
        )
        print(f"   ✔ Website hosting enabled for {bucket_name}")
    except Exception as e:
        print(f"   ⚠ Could not enable website hosting: {e}")


if __name__ == "__main__":
    print(f"🟦 S3 setup started (region={REGION})")

    create_bucket(FRONTEND_BUCKET)

    if ARTIFACT_BUCKET != FRONTEND_BUCKET:
        create_bucket(ARTIFACT_BUCKET)

    print("   ✔ S3 setup complete")
