import logging
from configparser import ConfigParser
from datetime import datetime
from pathlib import Path, PurePath
from sys import exit
from typing import Optional

import boto3

from aws_mfa.exceptions import (
    AwsCredentialsMissingSection,
    AwsCredentialsNoSharedCredentialsFileFound,
    AwsCredentialsNotFound,
    AwsCredentialsUsingEnvVars,
    CouldNotCreateAwsAccessKey,
    CouldNotDeleteAwsAccessKey,
    FailedToLoadCredentialsFile,
    InvalidTokenCode,
    NoAccessKeyReturnedFromAws,
    NoMfaDeviceFound,
)
from os import environ


class AwsCredentials:
    def _get_auth_method(self, session):
        if session.get_credentials():
            return session.get_credentials().method
        else:
            raise AwsCredentialsNotFound("No AWS credentials were found")

    def _get_client_for_profile(self, profile: str, svc: str) -> boto3.client:
        session = boto3.Session(profile_name=profile)
        self.aws_auth_method = self._get_auth_method(session)
        self.logger.debug("Using profile: %s with service %s" % (profile, svc))
        return session.client(svc)

    def __init__(
        self,
        creds_file_path: str,
        profile: str,
        logger: logging.Logger = logging.getLogger(),
    ):
        self.logger = logger
        self.profile = "default" if not profile else profile
        self.no_mfa_profile = f"{self.profile}-no-mfa"
        self.iam_client = self._get_client_for_profile(self.profile, "iam")
        self.sts_client = self._get_client_for_profile(self.profile, "sts")
        if self.aws_auth_method == "env" or environ.get("AWS_ACCESS_KEY_ID"):
            raise AwsCredentialsUsingEnvVars(
                "Using environment variables is not currently supported"
            )
        elif self.aws_auth_method != "shared-credentials-file":
            raise AwsCredentialsNoSharedCredentialsFileFound
        self.creds_file_path = (
            PurePath(creds_file_path)
            if creds_file_path
            else PurePath(Path.home(), ".aws/credentials")
        )
        self.aws_credentials_config = self.load_creds_file()
        self.username = self.iam_client.get_user()["User"]["UserName"]

    def _check_mfa_enabled(
        self, credentials_config: ConfigParser = ConfigParser()
    ) -> bool:
        if not credentials_config.sections():
            credentials_config = self.aws_credentials_config
        return (
            self.no_mfa_profile in credentials_config.sections()
            and self.profile in credentials_config.sections()
            and "aws_session_token" in credentials_config[self.profile]
        )

    def _use_non_mfa_profile(self) -> None:
        self.iam_client = self._get_client_for_profile(self.no_mfa_profile, "iam")
        self.sts_client = self._get_client_for_profile(self.no_mfa_profile, "sts")

    def load_creds_file(self) -> ConfigParser:
        self.logger.debug("Using %s as AWS credentials path" % self.creds_file_path)
        config = ConfigParser()
        config.read(str(self.creds_file_path))
        if self._check_mfa_enabled(config):
            self.logger.debug("MFA profile already exists in AWS credentials file")
            self._use_non_mfa_profile()
        return config

    def get_mfa_serial(self) -> Optional[int]:
        resp = self.iam_client.list_mfa_devices(UserName=self.username)
        if resp["MFADevices"]:
            return resp["MFADevices"][0][
                "SerialNumber"
            ]  # There should only ever be 1 MFA device, even though a list is returned
        else:
            raise NoMfaDeviceFound("No MFA device found for user")

    def get_credentials(self, duration: int, token: str) -> dict:
        try:
            return self.sts_client.get_session_token(
                DurationSeconds=duration,
                SerialNumber=self.get_mfa_serial(),
                TokenCode=token,
            )
        except self.sts_client.exceptions.ClientError as e:
            if "invalid MFA one time pass code" in str(e):
                raise InvalidTokenCode("Token code is invalid")
            else:
                raise e

    def get_access_key_age(self, profile: str = "") -> Optional[int]:
        """Gets access key using specified profile, or if not specified defaults to MFA enabled profile to prevent locking out the defaul profile when the access keys are deleted"""
        profile = self.no_mfa_profile if not profile else profile
        self.mfa_iam_client = self._get_client_for_profile(self.profile, "iam")
        try:
            access_key = self.aws_credentials_config[profile]["aws_access_key_id"]
        except KeyError:
            raise AwsCredentialsMissingSection(
                "section %s not found in %s" % (profile, str(self.creds_file_path))
            )
        resp = self.mfa_iam_client.list_access_keys(UserName=self.username)[
            "AccessKeyMetadata"
        ]
        for key in resp:
            if key["AccessKeyId"] == access_key.strip():
                created = key["CreateDate"].replace(tzinfo=None)
                now = datetime.utcnow()  # Returned datetime uses utc timezone
                diff = now - created
                return diff.days
        raise NoAccessKeyReturnedFromAws("No access Key returned from AWS")

    def update_access_keys(self) -> None:
        """Update the non-MFA access keys by deleting them then creating new ones"""
        try:
            type(self.mfa_iam_client)
        except AttributeError:
            self.mfa_iam_client = self._get_client_for_profile(self.profile, "iam")
        # If there is a 'no_mfa_profile' section and there is a session token in the profile we can assume this tool has been run
        if self._check_mfa_enabled():
            access_key = self.aws_credentials_config[self.no_mfa_profile][
                "aws_access_key_id"
            ]
            try:
                del_resp = self.mfa_iam_client.delete_access_key(
                    UserName=self.username, AccessKeyId=access_key
                )
            except self.mfa_iam_client.exceptions.ClientError:
                raise NoAccessKeyReturnedFromAws(
                    "Access key not found in response from AWS"
                )
            if del_resp["ResponseMetadata"]["HTTPStatusCode"] == 200:
                self.logger.debug("Successfully deleted access key %s" % access_key)
                create_resp = self.mfa_iam_client.create_access_key(
                    UserName=self.username
                )  #  The major error to avoid here would be if the access key limit were exceeded but that cannot happen if an access key was just deleted
                if create_resp["ResponseMetadata"]["HTTPStatusCode"] == 200:
                    new_access_key = create_resp["AccessKey"]["AccessKeyId"]
                    self.aws_credentials_config[self.no_mfa_profile] = {
                        "aws_access_key_id": new_access_key,
                        "aws_secret_access_key": create_resp["AccessKey"][
                            "SecretAccessKey"
                        ],
                    }
                    self.logger.debug(
                        "Successfully created new access key with ID %s"
                        % new_access_key
                    )
                    self.write_creds(self.aws_credentials_config)
                    return
                else:
                    raise CouldNotCreateAwsAccessKey(
                        "There was an error creating a new access key: %s"
                        % create_resp["ResponseMetadata"],
                    )
            else:
                raise CouldNotDeleteAwsAccessKey(
                    "There was an error deleting an access key %s: %s"
                    % (access_key, del_resp["ResponseMetadata"])
                )

    def update_mfa_credentials(self, new_credentials) -> None:
        """Update the MFA credentials - the one that uses a session token"""
        if not self.aws_credentials_config:
            raise FailedToLoadCredentialsFile(
                "Credentials could not be loaded from file %s" % self.creds_file_path
            )
        if not self._check_mfa_enabled():
            self.aws_credentials_config[
                self.no_mfa_profile
            ] = self.aws_credentials_config[self.profile]
        self.logger.debug(
            "Updating temporary credentials for profile %s with access key %s"
            % (self.profile, new_credentials["Credentials"]["AccessKeyId"])
        )
        self.aws_credentials_config[self.profile] = {
            "aws_access_key_id": new_credentials["Credentials"]["AccessKeyId"],
            "aws_secret_access_key": new_credentials["Credentials"]["SecretAccessKey"],
            "aws_session_token": new_credentials["Credentials"]["SessionToken"],
        }
        self.write_creds(self.aws_credentials_config)
        return new_credentials["Credentials"]["Expiration"]

    def write_creds(self, aws_creds_config) -> None:
        self.logger.debug("Writing new credentials to %s" % self.creds_file_path)
        with open(self.creds_file_path, "w") as aws_creds:
            aws_creds_config.write(aws_creds)
        self.logger.debug(
            "Credentials successfully written to %s" % self.creds_file_path
        )
