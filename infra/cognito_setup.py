#!/usr/bin/env python3
import os
import boto3
from botocore.exceptions import ClientError

REGION = os.getenv("AWS_REGION", "us-east-1")
PROJECT_NAME = os.getenv("PROJECT_NAME", "preethi-logistics")

def setup_cognito():
    client = boto3.client("cognito-idp", region_name=REGION)
    pool_name = f"{PROJECT_NAME}-pool"
    client_name = "web-client"

    print(f"🟦 Cognito setup (region={REGION})")

    # find existing pool
    pool_id = None
    try:
        resp = client.list_user_pools(MaxResults=60)
        for p in resp.get("UserPools", []):
            if p.get("Name") == pool_name:
                pool_id = p.get("Id")
                break
    except ClientError as e:
        print(f"   ⚠ Error listing user pools: {e}")

    # create if missing
    if not pool_id:
        try:
            r = client.create_user_pool(PoolName=pool_name, AutoVerifiedAttributes=["email"])
            pool_id = r["UserPool"]["Id"]
            print(f"   ✔ Created User Pool: {pool_id}")
        except ClientError as e:
            print(f"   ✖ Failed to create user pool: {e}")
            raise
    else:
        print(f"   ✔ User Pool exists: {pool_id}")

    # find / create app client
    app_client_id = None
    try:
        resp = client.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60)
        for c in resp.get("UserPoolClients", []):
            if c.get("ClientName") == client_name:
                app_client_id = c.get("ClientId")
                break
    except ClientError as e:
        print(f"   ⚠ Error listing pool clients: {e}")

    if not app_client_id:
        try:
            r = client.create_user_pool_client(
                UserPoolId=pool_id,
                ClientName=client_name,
                GenerateSecret=False,
                ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
            )
            app_client_id = r["UserPoolClient"]["ClientId"]
            print(f"   ✔ Created App Client: {app_client_id}")
        except ClientError as e:
            print(f"   ✖ Failed to create app client: {e}")
            raise
    else:
        print(f"   ✔ App Client exists: {app_client_id}")

    # create groups if not present
    for group in ("agent", "customer"):
        try:
            client.create_group(UserPoolId=pool_id, GroupName=group)
            print(f"   ✔ Created group: {group}")
        except ClientError as e:
            # ignore if exists
            if e.response.get("Error", {}).get("Code") in ("GroupExistsException",):
                print(f"   ✔ Group exists: {group}")
            else:
                print(f"   ⚠ Could not create group {group}: {e}")

    # Print outputs for GitHub Actions
    print(f"OUTPUT_COGNITO_POOL_ID={pool_id}")
    print(f"OUTPUT_COGNITO_CLIENT_ID={app_client_id}")

    return pool_id, app_client_id

if __name__ == "__main__":
    setup_cognito()
