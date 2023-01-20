from configparser import ConfigParser
from os import path, remove

import boto3
import pytest
from freezegun import freeze_time
from moto import mock_iam, mock_sts

from src.aws_credentials import AwsCredentials


# TODO:
# check_mfa_enabled
# mfa_is_enabled
# load_creds_file
# get_mfa_serial
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
        client.enable_mfa_device(
            UserName="default_user",
            SerialNumber=resp_create_mfa["VirtualMFADevice"]["SerialNumber"],
            AuthenticationCode1="123456",
            AuthenticationCode2="654321",
        )
        config = ConfigParser()
        config["default"] = {
            "aws_access_key_id": resp["AccessKey"]["AccessKeyId"],
            "aws_secret_access_key": resp["AccessKey"]["SecretAccessKey"],
        }
        creds_path = f"{path.dirname(__file__)}/aws_credentials"
        mocker.patch(
            "src.aws_credentials.AwsCredentials._get_auth_method",
            return_value="shared-credentials-file",
        )
        with open(creds_path, "x") as f:
            config.write(f)
        with mock_sts():
            yield creds_path
        if path.isfile(creds_path):
            remove(creds_path)


@freeze_time("2022-12-31")
def test_get_access_key_age(create_access_keys):
    """Tests function can get accurate age of key"""
    aws_creds = AwsCredentials(
        creds_file_path=str(create_access_keys), profile="default"
    )
    access_key_age = aws_creds.get_access_key_age("default")
    assert access_key_age == 91


def test_update_mfa_credentials_no_existing_mfa(create_access_keys):
    """Tests adding MFA credentials to a shared credentials file when no MFA credentials currently exist"""
    aws_creds = AwsCredentials(
        creds_file_path=str(create_access_keys), profile="default"
    )
    config = ConfigParser()
    config.read(str(create_access_keys))
    assert config.has_option("default", "aws_access_key_id")
    assert config.has_option("default", "aws_secret_access_key")
    assert not config.has_option("default-no-mfa", "aws_session_token")
    aws_creds.update_mfa_credentials(
        aws_creds.get_credentials(duration=900, token="123456")
    )
    config.read(str(create_access_keys))
    assert config.has_section("default-no-mfa")
    assert config.has_option("default", "aws_session_token")


def test_update_mfa_credentials_with_existing_mfa(create_access_keys):
    """Tests adding MFA credentials to a shared credentials file when MFA credentials already exist"""
    aws_creds = AwsCredentials(
        creds_file_path=str(create_access_keys), profile="default"
    )
    config = ConfigParser()
    config.read(str(create_access_keys))
    old_expire = aws_creds.update_mfa_credentials(
        aws_creds.get_credentials(duration=900, token="123456")
    )
    config.read(str(create_access_keys))
    assert config.has_section("default")
    assert config.has_option("default", "aws_access_key_id")
    assert config.has_option("default", "aws_secret_access_key")
    assert config.has_option("default", "aws_session_token")
    assert config.has_section("default-no-mfa")
    assert config.has_option("default-no-mfa", "aws_access_key_id")
    old_access_key_id = config["default-no-mfa"].get("aws_access_key_id")
    old_secret_access_key = config["default-no-mfa"].get("aws_secret_access_key")
    new_expire = aws_creds.update_mfa_credentials(
        aws_creds.get_credentials(duration=900, token="123456")
    )
    config.read(str(create_access_keys))
    new_access_key_id = config["default-no-mfa"].get("aws_access_key_id")
    new_secret_access_key = config["default-no-mfa"].get("aws_secret_access_key")
    assert new_access_key_id == old_access_key_id
    assert new_secret_access_key == old_secret_access_key
    # Moto mocks the session token, but will always return the same one - so we need to look at expiry to verify it changed
    assert old_expire != new_expire


def test_update_access_keys(create_access_keys):
    aws_creds = AwsCredentials(
        creds_file_path=str(create_access_keys), profile="default"
    )
    aws_creds.update_mfa_credentials(
        aws_creds.get_credentials(duration=900, token="123456")
    )
    config = ConfigParser()
    config.read(str(create_access_keys))
    old_access_key_id = config["default-no-mfa"].get("aws_access_key_id")
    old_secret_access_key = config["default-no-mfa"].get("aws_secret_access_key")
    old_mfa_access_key_id = config["default"].get("aws_access_key_id")
    old_mfa_secret_access_key = config["default"].get("aws_secret_access_key")
    old_mfa_session_token = config["default"]["aws_session_token"]
    aws_creds.update_access_keys()
    config.read(str(create_access_keys))
    new_access_key_id = config["default-no-mfa"].get("aws_access_key_id")
    new_secret_access_key = config["default-no-mfa"].get("aws_secret_access_key")
    new_mfa_access_key_id = config["default"].get("aws_access_key_id")
    new_mfa_secret_access_key = config["default"].get("aws_secret_access_key")
    new_mfa_session_token = config["default"]["aws_session_token"]
    assert old_access_key_id != new_access_key_id
    assert old_secret_access_key != new_secret_access_key
    assert old_mfa_access_key_id == new_mfa_access_key_id
    assert old_mfa_secret_access_key == new_mfa_secret_access_key
    assert old_mfa_session_token == new_mfa_session_token
