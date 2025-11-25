#!/usr/bin/env python3
import os
import boto3

REGION = os.getenv("AWS_REGION", "us-east-1")
PROJECT = os.getenv("PROJECT_NAME", "preethi-logistics")

def upload_ssm_params():
    ssm = boto3.client("ssm", region_name=REGION)

    maps_key = os.getenv("GOOGLE_MAPS_API_KEY")
    google_creds_json = os.getenv("GOOGLE_CREDS_JSON")

    print(f"🟦 SSM setup (region={REGION})")

    if maps_key:
        try:
            ssm.put_parameter(
                Name=f"/{PROJECT}/google-maps-key",
                Value=maps_key,
                Type="SecureString",
                Overwrite=True
            )
            print("   ✔ google-maps-key uploaded to SSM")
        except Exception as e:
            print(f"   ✖ Failed to upload google-maps-key: {e}")

    if google_creds_json:
        try:
            ssm.put_parameter(
                Name=f"/{PROJECT}/google-creds",
                Value=google_creds_json,
                Type="SecureString",
                Overwrite=True
            )
            print("   ✔ google-creds uploaded to SSM")
        except Exception as e:
            print(f"   ✖ Failed to upload google-creds: {e}")

    if not maps_key and not google_creds_json:
        print("   ⚠ No SSM secrets provided; skipped.")

if __name__ == "__main__":
    upload_ssm_params()
