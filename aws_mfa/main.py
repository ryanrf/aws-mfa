#!/usr/bin/env python
import click
import logging
from sys import stdout
from aws_mfa.aws_credentials import AwsCredentials, user_prompt

logger = logging.getLogger(__name__)
ch = logging.StreamHandler(stdout)
formatter = logging.Formatter("[%(levelname)s] %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

ACCESS_KEY_AGE_LIMIT_DAYS = 90


@click.command()
@click.option(
    "--token",
    "-t",
    required=True,
    help="Temporary One Time Password, aka Token used with MFA",
)
@click.option(
    "--duration",
    "-d",
    required=False,
    default=43200,
    help="Duration for temporary credentials to be valid, default is 12h",
)
@click.option(
    "--profile",
    "-p",
    required=False,
    default=None,
    help="Profile to use for getting (and setting) MFA credentials, uses 'default' profile by default",
)
@click.option(
    "--credentials",
    "-c",
    required=False,
    default=None,
    help="Path to AWS credentials file, default is '$HOME/.aws/credentials'",
)
@click.option(
    "--verbose",
    "-v",
    required=False,
    is_flag=True,
    default=False,
    help="Enable more verbose (INFO) level logging",
)
def main(token, duration, profile, credentials, verbose):
    if verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARN)
    aws_credentials = AwsCredentials(
        creds_file_path=credentials, profile=profile, logger=logger
    )
    first_run = True if not aws_credentials.mfa_enabled else False
    aws_credentials.update_credentials(
        new_credentials=aws_credentials.get_credentials(duration, token)
    )
    access_key_age = aws_credentials.get_access_key_age()
    if (
        aws_credentials.get_access_key_age()
        and access_key_age > ACCESS_KEY_AGE_LIMIT_DAYS
    ):
        print(f"\nLooks like your access key is {access_key_age} days old.")
        update = user_prompt(
            msg="Would you like to update your access keys now?",
            valid_ans=["yes", "no"],
            logger=logger,
        )
        if update.strip() == "yes":
            aws_credentials.update_access_keys()
        else:
            print("Not updating access key at this time")


if __name__ == "__main__":
    main()
