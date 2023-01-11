import boto3
import logging
from os import environ
from sys import exit
from configparser import ConfigParser
from pathlib import Path, PurePath
from datetime import datetime
from typing import Optional

# Also need to consider handling AWS env var, or at least alerting users when they exist


class AwsCredentials:
    def __init__(
        self,
        creds_file_path: str,
        profile: str,
        logger: logging.Logger = logging.getLogger(),
    ):
        self.logger = logger
        env_var_creds = environ.get("AWS_ACCESS_KEY_ID")
        if env_var_creds:
            self.logger.error(
                f"AWS environment variables detected. Found access key {env_var_creds}. Please unset those environment variables before running this tool."
            )
            exit(1)
        self.creds_file_path = (
            PurePath(creds_file_path)
            if creds_file_path
            else PurePath(Path.home(), ".aws/credentials")
        )
        self.profile = "default" if not profile else profile
        self.no_mfa_profile = f"{self.profile}-no-mfa"
        self.mfa_enabled = False
        self.iam_client = self._set_aws_profile(self.profile, "iam")
        self.sts_client = self._set_aws_profile(self.profile, "sts")
        self.aws_credentials_config = self.load_creds_file()
        self.mfa_iam_client = None
        self.username = self.iam_client.get_user()["User"]["UserName"]

    def _set_aws_profile(self, profile: str, svc: str) -> boto3.client:
        session = boto3.Session(profile_name=profile)
        self.logger.info("Using profile: %s with service %s" % (profile, svc))
        return session.client(svc)

    def _check_mfa_enabled(self, credentials_config: ConfigParser = None) -> None:
        if not credentials_config:
            credentials_config = self.aws_credentials_config
        return (
            self.no_mfa_profile in credentials_config.sections()
            and self.profile in credentials_config.sections()
            and "aws_session_token" in credentials_config[self.profile]
        )

    def _mfa_is_enabled(self) -> None:
        self.iam_client = self._set_aws_profile(self.no_mfa_profile, "iam")
        self.sts_client = self._set_aws_profile(self.no_mfa_profile, "sts")
        self.mfa_enabled = True

    def load_creds_file(self) -> ConfigParser():
        self.logger.info("Using %s as AWS credentials path" % self.creds_file_path)
        config = ConfigParser()
        config.read(str(self.creds_file_path))
        if self._check_mfa_enabled(config):
            self.logger.info("MFA profile already exists in AWS credentials file")
            self._mfa_is_enabled()
        return config

    def get_mfa_serial(self) -> Optional[int]:
        resp = self.iam_client.list_mfa_devices(UserName=self.username)
        if resp["MFADevices"]:
            return resp["MFADevices"][0][
                "SerialNumber"
            ]  # There should only ever be 1 MFA device, even though a list is returned
        else:
            self.logger.error(
                "User %s does not have any MFA devices configured" % self.username
            )

    def get_credentials(self, duration: int, token: str) -> dict:
        return self.sts_client.get_session_token(
            DurationSeconds=duration,
            SerialNumber=self.get_mfa_serial(),
            TokenCode=token,
        )

    def get_access_key_age(self, profile: str = None) -> Optional[int]:
        """Gets access key using specified profile, or if not specified defaults to MFA enabled profile to prevent locking out the defaul profile when the access keys are deleted"""
        profile = self.no_mfa_profile if not profile else profile
        self.mfa_iam_client = self._set_aws_profile(self.profile, "iam")
        try:
            access_key = self.aws_credentials_config[profile]["aws_access_key_id"]
        except KeyError:
            raise KeyError(
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
        self.logger.error("No access key found for user %s" % self.username)

    def update_access_keys(self) -> None:
        """Update the non-MFA access keys by deleting them then creating new ones"""
        if not self.mfa_iam_client:
            self.mfa_iam_client = self._set_aws_profile(self.profile, "iam")
        # If there is a 'no_mfa_profile' section and there is a session token in the profile we can assume this tool has been run
        if self._check_mfa_enabled:
            access_key = self.aws_credentials_config[self.no_mfa_profile][
                "aws_access_key_id"
            ]
            try:
                del_resp = self.mfa_iam_client.delete_access_key(
                    UserName=self.username, AccessKeyId=access_key
                )
            except self.mfa_iam_client.exceptions.ClientError:
                self.logger.error(
                    "access key not found in profile %s" % self.no_mfa_profile
                )
                return
            if del_resp["ResponseMetadata"]["HTTPStatusCode"] == 200:
                self.logger.info("Successfully deleted access key %s" % access_key)
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
                    self.logger.info(
                        "Successfully created new access key with ID %s"
                        % new_access_key
                    )
                    self.write_creds(self.aws_credentials_config)
                    return
                else:
                    self.logger.error(
                        "There was an issue creating the access key: %s"
                        % create_resp["ResponseMetadata"]
                    )
                    return
            else:
                self.logger.error(
                    "An error occured deleting access key %s: %s"
                    % (access_key, del_resp["ResponseMetadata"])
                )

    def update_credentials(self, new_credentials) -> None:
        if not self.aws_credentials_config:
            raise ValueError(
                "Credentials could not be loaded from file %s" % self.creds_file_path
            )
        if not self.mfa_enabled:
            self.aws_credentials_config[
                self.no_mfa_profile
            ] = self.aws_credentials_config[self.profile]
        self.logger.info(
            "Updating temporary credentials for profile %s with access key %s"
            % (self.profile, new_credentials["Credentials"]["AccessKeyId"])
        )
        self.aws_credentials_config[self.profile] = {
            "aws_access_key_id": new_credentials["Credentials"]["AccessKeyId"],
            "aws_secret_access_key": new_credentials["Credentials"]["SecretAccessKey"],
            "aws_session_token": new_credentials["Credentials"]["SessionToken"],
        }
        self.write_creds(self.aws_credentials_config)

    def write_creds(self, aws_creds_config) -> None:
        self.logger.info("Writing new credentials to %s" % self.creds_file_path)
        with open(self.creds_file_path, "w") as aws_creds:
            aws_creds_config.write(aws_creds)
        self.logger.info(
            "Credentials successfully written to %s" % self.creds_file_path
        )


def user_prompt(
    msg: str,
    valid_ans: list[str] = ["yes", "no"],
    affirmative: str = "yes",
):
    if affirmative not in valid_ans:
        raise ValueError("%s is not in %s" % (affirmative, valid_ans))
    msg = f"{msg}[{'/'.join(valid_ans)}] "
    # Picking an arbitrary range to avoid any chance of getting stuck in a loop
    for i in range(5):
        user_input = input(msg).strip()
        if user_input in valid_ans and user_input == affirmative:
            return True
        elif user_input in valid_ans and user_input != affirmative:
            return False
        print(f"Invalid user input. Allowed values: {valid_ans}")
    return False
