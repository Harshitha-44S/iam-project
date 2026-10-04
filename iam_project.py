#!/usr/bin/env python3
"""
AWS IAM Minor Project - Roles, Policies & Permission Best Practices
Runs fully offline on Moto (an AWS emulator) with IAM policy enforcement ON.

Run:  pip install "moto[all]" boto3
      python iam_project.py
Output is printed to the terminal and saved to results.json / iam_project_output.txt
"""
import json
import os
import sys

# Make Moto load AWS managed policies (ReadOnlyAccess, AmazonS3ReadOnlyAccess ...)
os.environ["MOTO_IAM_LOAD_MANAGED_POLICIES"] = "true"
from botocore.exceptions import ClientError
import boto3
from moto import mock_aws
from moto.core.authorization import enable_iam_authentication, disable_iam_authentication

REGION = "ap-south-1"
BUCKET = "company-project-storage"
ACCOUNT = "123456789012"  # Moto default account id

USERS = {
    "Developers": ["developer1", "developer2"],
    "DevOps": ["devops1", "devops2"],
    "Auditors": ["auditor1", "auditor2"],
}

DEVELOPERS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ListBucket",
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": f"arn:aws:s3:::{BUCKET}",
        },
        {
            "Sid": "ObjectReadWrite",
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": f"arn:aws:s3:::{BUCKET}/*",
        },
    ],
}

DEVOPS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Ec2Lifecycle",
            "Effect": "Allow",
            "Action": [
                "ec2:RunInstances",
                "ec2:StartInstances",
                "ec2:StopInstances",
                "ec2:RebootInstances",
                "ec2:TerminateInstances",
                "ec2:Describe*",
                "ec2:CreateTags",
            ],
            "Resource": "*",
        },
        {
            "Sid": "CloudWatchAccess",
            "Effect": "Allow",
            "Action": ["cloudwatch:*", "logs:Describe*", "logs:Get*"],
            "Resource": "*",
        },
        {
            "Sid": "ReadOnlyVpcAndIamRoles",
            "Effect": "Allow",
            "Action": ["iam:ListRoles", "iam:GetRole", "iam:ListInstanceProfiles"],
            "Resource": "*",
        },
    ],
}

EC2_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

results = []


def log(msg=""):
    print(msg)


def attempt(label, user, action, expected, fn):
    """Run fn(); record Success / Access Denied and compare with the expected value."""
    try:
        fn()
        actual = "Success"
    except ClientError as e:
        code = e.response["Error"]["Code"]
        actual = "Access Denied" if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation") else f"Error: {code}"
    verdict = "PASS" if actual == expected else "FAIL"
    results.append(
        {"user": user, "action": action, "expected": expected, "result": actual, "verdict": verdict}
    )
    log(f"  [{verdict}] {user:<11} {action:<28} expected={expected:<14} got={actual}")
    return actual == expected


@mock_aws
def main():
    iam = boto3.client("iam", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)
    ec2 = boto3.client("ec2", region_name=REGION)

    log("=" * 70)
    log("STEP 1: Setup as the account administrator (no restrictions)")
    log("=" * 70)

    # --- groups and users
    for group, members in USERS.items():
        iam.create_group(GroupName=group)
        log(f"  Created group: {group}")
        for u in members:
            iam.create_user(UserName=u)
            iam.add_user_to_group(GroupName=group, UserName=u)
            log(f"  Created user:  {u}  ->  {group}")

    # --- S3 bucket + sample files
    s3.create_bucket(
        Bucket=BUCKET,
        CreateBucketConfiguration={"LocationConstraint": REGION},
    )
    for name in ("report.txt", "data.csv"):
        s3.put_object(Bucket=BUCKET, Key=f"samples/{name}", Body=b"sample content")
    log(f"  Created bucket {BUCKET} with 2 sample files")

    # --- custom policies
    dev_pol = iam.create_policy(
        PolicyName="DevelopersS3Policy", PolicyDocument=json.dumps(DEVELOPERS_POLICY)
    )["Policy"]["Arn"]
    ops_pol = iam.create_policy(
        PolicyName="DevOpsEC2Policy", PolicyDocument=json.dumps(DEVOPS_POLICY)
    )["Policy"]["Arn"]
    log("  Created custom policies: DevelopersS3Policy, DevOpsEC2Policy")

    iam.attach_group_policy(GroupName="Developers", PolicyArn=dev_pol)
    iam.attach_group_policy(GroupName="DevOps", PolicyArn=ops_pol)
    iam.attach_group_policy(
        GroupName="Auditors", PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess"
    )
    log("  Attached policies to groups (Auditors -> AWS managed ReadOnlyAccess)")

    # --- EC2 role + instance profile + instance
    iam.create_role(
        RoleName="EC2-S3-Access-Role",
        AssumeRolePolicyDocument=json.dumps(EC2_TRUST_POLICY),
    )
    iam.attach_role_policy(
        RoleName="EC2-S3-Access-Role",
        PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    )
    iam.create_instance_profile(InstanceProfileName="EC2-S3-Access-Role")
    iam.add_role_to_instance_profile(
        InstanceProfileName="EC2-S3-Access-Role", RoleName="EC2-S3-Access-Role"
    )
    image_id = ec2.describe_images()["Images"][0]["ImageId"]
    inst = ec2.run_instances(
        ImageId=image_id,
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
        IamInstanceProfile={"Name": "EC2-S3-Access-Role"},
    )["Instances"][0]["InstanceId"]
    log(f"  Created role EC2-S3-Access-Role, attached to EC2 instance {inst}")

    # --- MFA for developer1, forced password reset for developer2
    mfa = iam.create_virtual_mfa_device(VirtualMFADeviceName="developer1-mfa")[
        "VirtualMFADevice"
    ]
    mfa_status = "enabled"
    try:
        iam.enable_mfa_device(
            UserName="developer1",
            SerialNumber=mfa["SerialNumber"],
            AuthenticationCode1="123456",
            AuthenticationCode2="654321",
        )
        log("  MFA device enabled for developer1")
    except ClientError as e:
        mfa_status = f"not enabled in emulator ({e.response['Error']['Code']})"
        log(f"  MFA enable skipped by emulator: {mfa_status}")

    iam.create_login_profile(
        UserName="developer2", Password="TempPassw0rd!2026", PasswordResetRequired=True
    )
    log("  developer2 console password created with PasswordResetRequired=True")

    # --- access keys, one set per user
    keys = {}
    for members in USERS.values():
        for u in members:
            k = iam.create_access_key(UserName=u)["AccessKey"]
            keys[u] = (k["AccessKeyId"], k["SecretAccessKey"])

    def client_for(service, user):
        ak, sk = keys[user]
        return boto3.client(
            service,
            region_name=REGION,
            aws_access_key_id=ak,
            aws_secret_access_key=sk,
        )

    log()
    log("=" * 70)
    log("STEP 2: Validate permissions (IAM policy enforcement ON)")
    log("=" * 70)

    with enable_iam_authentication():
        # --- the four tests required by the project
        attempt(
            "t1", "developer1", "Upload object", "Success",
            lambda: client_for("s3", "developer1").put_object(
                Bucket=BUCKET, Key="uploads/dev1.txt", Body=b"hello"
            ),
        )
        attempt(
            "t2", "developer1", "Delete bucket", "Access Denied",
            lambda: client_for("s3", "developer1").delete_bucket(Bucket=BUCKET),
        )
        attempt(
            "t3", "auditor1", "Create EC2", "Access Denied",
            lambda: client_for("ec2", "auditor1").run_instances(
                ImageId=image_id, MinCount=1, MaxCount=1, InstanceType="t2.micro"
            ),
        )
        attempt(
            "t4", "devops1", "Terminate EC2", "Success",
            lambda: client_for("ec2", "devops1").terminate_instances(InstanceIds=[inst]),
        )

        log()
        log("  Extra checks (least privilege and group behaviour):")
        attempt(
            "x1", "developer2", "Download object", "Success",
            lambda: client_for("s3", "developer2").get_object(
                Bucket=BUCKET, Key="samples/report.txt"
            ),
        )
        attempt(
            "x2", "developer1", "Delete object", "Access Denied",
            lambda: client_for("s3", "developer1").delete_object(
                Bucket=BUCKET, Key="samples/report.txt"
            ),
        )
        attempt(
            "x3", "developer2", "Create EC2", "Access Denied",
            lambda: client_for("ec2", "developer2").run_instances(
                ImageId=image_id, MinCount=1, MaxCount=1, InstanceType="t2.micro"
            ),
        )
        attempt(
            "x4", "devops2", "Create EC2", "Success",
            lambda: client_for("ec2", "devops2").run_instances(
                ImageId=image_id, MinCount=1, MaxCount=1, InstanceType="t2.micro"
            ),
        )
        attempt(
            "x5", "devops1", "Delete bucket", "Access Denied",
            lambda: client_for("s3", "devops1").delete_bucket(Bucket=BUCKET),
        )
        attempt(
            "x6", "auditor2", "List S3 objects (read)", "Success",
            lambda: client_for("s3", "auditor2").list_objects_v2(Bucket=BUCKET),
        )
        attempt(
            "x7", "auditor1", "Upload object (write)", "Access Denied",
            lambda: client_for("s3", "auditor1").put_object(
                Bucket=BUCKET, Key="uploads/aud.txt", Body=b"x"
            ),
        )

    passed = sum(r["verdict"] == "PASS" for r in results)
    log()
    log("=" * 70)
    log(f"SUMMARY: {passed}/{len(results)} checks matched the expected result")
    log("=" * 70)

    with disable_iam_authentication():
        summary = {
            "groups": {g: iam.get_group(GroupName=g)["Users"].__len__() for g in USERS},
            "mfa": mfa_status,
            "instance_profile": inst,
            "results": results,
        }
    with open("results.json", "w") as f:
        json.dump(summary, f, indent=2, default=str)
    log("Saved: results.json")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())