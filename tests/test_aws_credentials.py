import pytest
import boto3
from moto import mock_iam, mock_sts
from aws_mfa.aws_credentials import AwsCredentials
from freezegun import freeze_time
from configparser import ConfigParser
from os import path, remove
from datetime import datetime, timedelta


@pytest.fixture
def create_access_keys(mocker):
    with mock_iam():
        client = boto3.client("iam")
        client.create_user(UserName="default_user")
        with freeze_time("2022-10-01"):
            resp = client.create_access_key(UserName="default_user")
        resp_create_mfa = client.create_virtual_mfa_device(
            VirtualMFADeviceName="mfa_device"
        )
        config = ConfigParser()
        config["default"] = {
            "aws_access_key_id": resp["AccessKey"]["AccessKeyId"],
            "aws_secret_access_key": resp["AccessKey"]["SecretAccessKey"],
        }
        creds_path = f"{path.dirname(__file__)}/data/aws_credentials"
        mocker.patch(
            "aws_mfa.aws_credentials.AwsCredentials._get_auth_method",
            return_value="shared-credentials-file",
        )
        mocker.patch(
            "aws_mfa.aws_credentials.AwsCredentials.get_credentials",
            return_value={
                "Credentials": {
                    "AccessKeyId": "ASIAXWYTZFZG7JGNJ7NJ",
                    "SecretAccessKey": "Y5HTl96F6JfXf5prTcWb4C1hmdfeKqqE3EyKS9Xj",
                    "SessionToken": "FwoGZXIvYXdzEHoaDHjfqrylgeadKYYMdoKGATnGQmLz+nL3zKh9iUFbnprIGbrwWCq+ZszRB5QE8perGc3wkawW4LQrejJ25Qbp3bYnEbixzUrd/aJQsbwmzXAEYqQr1WM+kt1jO7XFR5b0A/k5/mNB3zV+uwtYfYUbR5iRhK6zmlpDwqycxxZ+49UU/5tDr/bRqloejiR3QQA7YXl0kwomKO/xgJ4GMigNGoinTt/PSj47s58jkEh5TB9U0KkqHjaazRGWB9zVeuMRRzHAohuy",
                    "Expiration": datetime.utcnow() + timedelta(hours=12),
                }
            },
        )
        with open(creds_path, "x") as f:
            config.write(f)
        yield creds_path
        if path.isfile(creds_path):
            remove(creds_path)


# check_mfa_enabled
# mfa_is_enabled
# load_creds_file
# get_mfa_serial
#
# More important
#
# get_access_key_age X
# update_access_keys
# update_mfa_credentials X


@freeze_time("2022-12-31")
def test_get_access_key_age(create_access_keys):
    aws_creds = AwsCredentials(
        creds_file_path=str(create_access_keys), profile="default"
    )
    access_key_age = aws_creds.get_access_key_age("default")
    assert access_key_age == 91


def test_update_mfa_credentials(create_access_keys):
    aws_creds = AwsCredentials(
        creds_file_path=str(create_access_keys), profile="default"
    )
    config = ConfigParser()
    config.read(str(create_access_keys))
    assert config.has_section("default")
    assert config.has_option("default", "aws_access_key_id")
    assert config.has_option("default", "aws_secret_access_key")
    assert not config.has_section("default-no-mfa")
    assert not config.has_option("default-no-mfa", "aws_session_token")
    aws_creds.update_mfa_credentials(
        aws_creds.get_credentials(duration=12, token=123456)
    )
    config.read(str(create_access_keys))
    assert config.has_section("default-no-mfa")
    assert config.has_option("default", "aws_session_token")


def test_update_access_keys(create_access_keys):
    pass


# update the access keys with MFA enabled
# attempt to update access keys without MFA enabled
