#!/usr/bin/env python3
import os
import json
import boto3
from botocore.exceptions import ClientError

REGION = os.getenv("AWS_REGION", "us-east-1")
FRONTEND_BUCKET = os.getenv("FRONTEND_BUCKET", "route-optimization-frontend")
ARTIFACT_BUCKET = os.getenv("ARTIFACT_S3_BUCKET", FRONTEND_BUCKET)

def create_bucket(bucket_name):
    s3 = boto3.client("s3", region_name=REGION)
    try:
        s3.create_bucket(
            Bucket=bucket_name
        )
        print(f"   ✔ Created S3 bucket: {bucket_name}")
    except ClientError as e:
        if "BucketAlreadyOwnedByYou" in str(e) or e.response.get("Error", {}).get("Code") in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            print(f"   ✔ Bucket exists: {bucket_name}")
        else:
            print(f"   ✖ Failed to create bucket {bucket_name}: {e}")
            raise

    # Configure public access block (if you want public hosting; adjust to policy)
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            }
        )
    except Exception as e:
        print(f"   ⚠ Could not set PublicAccessBlock for {bucket_name}: {e}")

    # Put bucket policy for public reads (if intended)
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicRead",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket_name}/*"
        }]
    }
    try:
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
    except ClientError as e:
        # some accounts may prevent public policies
        print(f"   ⚠ Could not put bucket policy for {bucket_name}: {e}")

    # Enable website hosting (optional)
    try:
        s3.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": "index.html"},
                "ErrorDocument": {"Key": "index.html"}
            }
        )
    except ClientError as e:
        print(f"   ⚠ Could not enable website hosting for {bucket_name}: {e}")

if __name__ == "__main__":
    print(f"🟦 S3 setup (region={REGION})")
    create_bucket(FRONTEND_BUCKET)
    if ARTIFACT_BUCKET != FRONTEND_BUCKET:
        create_bucket(ARTIFACT_BUCKET)
    print("   ✔ S3 setup complete")
