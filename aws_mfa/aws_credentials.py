import boto3
import logging
from configparser import ConfigParser
from pathlib import Path, PurePath


class AwsCredentials:
    def __init__(self, creds_file_path, profile, logger=logging.getLogger()):
        self.profile = "default" if not profile else profile
        self.no_mfa_profile = f"{self.profile}-no-mfa"
        self.iam_client = self._set_aws_profile(profile, "iam")
        self.sts_client = self._set_aws_profile(profile, "sts")
        self.creds_file_path = (
            PurePath(creds_file_path)
            if creds_file_path
            else PurePath(Path.home(), ".aws/credentials")
        )
        self.mfa_enabled = False
        self.logger = logger

    def _set_aws_profile(self, profile, svc):
        session = boto3.Session(profile_name=profile)
        return session.client(svc)

    def _mfa_is_enabled(self):
        self.iam_client = self._set_aws_profile(self.no_mfa_profile, "iam")
        self.sts_client = self._set_aws_profile(self.no_mfa_profile, "sts")
        self.mfa_enabled = True

    def load_creds_file(self):
        self.logger.info("Using %s as AWS credentials path" % self.creds_file_path)
        config = ConfigParser()
        config.read(str(self.creds_file_path))
        if self.no_mfa_profile in config.sections():
            self.logger.info("MFA profile already exists in AWS credentials file")
            self.logger.info(
                "Using '%s' profile for requests to IAM and STS" % self.no_mfa_profile
            )
            self._mfa_is_enabled()
        return config

    def get_mfa_serial(self):
        username = self.iam_client.get_user()["User"]["UserName"]
        resp = self.iam_client.list_mfa_devices(UserName=username)
        if resp["MFADevices"]:
            return resp["MFADevices"][0][
                "SerialNumber"
            ]  # There should only ever be 1 MFA device, even though a list is returned
        else:
            logging.error("User %s does not have any MFA devices configured" % username)

    def get_credentials(self, duration, token):
        return self.sts_client.get_session_token(
            DurationSeconds=duration,
            SerialNumber=self.get_mfa_serial(),
            TokenCode=token,
        )

    def update_credentials(self, aws_config, new_credentials):
        if not self.mfa_enabled:
            aws_config[self.no_mfa_profile] = aws_config[self.profile]
        aws_config[self.profile] = {
            "aws_access_key_id": new_credentials["Credentials"]["AccessKeyId"],
            "aws_secret_access_key": new_credentials["Credentials"]["SecretAccessKey"],
            "aws_session_token": new_credentials["Credentials"]["SessionToken"],
        }
        self.write_creds(aws_config)
        self.logger.info(
            "Credentials successfully written to %s" % self.creds_file_path
        )

    def write_creds(self, aws_creds_config):
        self.logger.info("Writing new credentials to %s" % self.creds_file_path)
        with open(self.creds_file_path, "w") as aws_creds:
            aws_creds_config.write(aws_creds)
