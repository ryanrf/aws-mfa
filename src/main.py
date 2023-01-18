#!/usr/bin/env python
import logging
from sys import exit, stdout

import click

from src.aws_credentials import AwsCredentials
from src.constants import ACCESS_KEY_AGE_LIMIT_DAYS, SETUP_HELP
from src.exceptions import (
    AwsCredentialsNoSharedCredentialsFileFound,
    AwsCredentialsNotFound,
    AwsCredentialsUsingEnvVars,
    CouldNotCreateAwsAccessKey,
    CouldNotDeleteAwsAccessKey,
    InvalidTokenCode,
    NoAccessKeyReturnedFromAws,
    NoMfaDeviceFound,
)

logger = logging.getLogger(__name__)
ch = logging.StreamHandler(stdout)
formatter = logging.Formatter("[%(levelname)s] %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)


@click.command()
@click.option(
    "--token",
    "-t",
    required=True,
    help="Temporary One Time Password, aka Token used with MFA",
    prompt="Enter token: ",
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
@click.option(
    "--force",
    "-f",
    required=False,
    is_flag=True,
    default=False,
    help="Force the replacement of non-MFA access keys",
)
def main(token, duration, profile, credentials, verbose, force):
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    try:
        aws_credentials = AwsCredentials(
            creds_file_path=credentials, profile=profile, logger=logger
        )
    except AwsCredentialsUsingEnvVars:
        logger.error(
            (
                "Using environment variables to store AWS credentials is not supported by this tool.",
                "\n\nPlease unset 'AWS_ACCESS_KEY' and 'AWS_SECRET_ACCESS_KEY' environment variables and rerun this tool.",
                SETUP_HELP,
            )
        )
        exit(1)
    except AwsCredentialsNotFound:
        logger.error(
            (
                "Could not find any AWS credentials. This could be an issue of missing credentials file, or specifying the wrong profile.\n%s",
                SETUP_HELP,
            )
        )
        exit(1)
    except AwsCredentialsNoSharedCredentialsFileFound:
        logger.error(
            (
                "Unsupported authentication method detected.\n\nThe only authentication method supported by this tool is using a shared credentials file (i.e. ~/.aws/credentials)\n %s",
                SETUP_HELP,
            )
        )
        exit(1)
    try:
        expire = aws_credentials.update_mfa_credentials(
            new_credentials=aws_credentials.get_credentials(duration, token)
        )
    except NoMfaDeviceFound:
        logger.error("User does not have any MFA devices configured")
        exit(1)
    except InvalidTokenCode:
        logger.error("Token is invalid")
        exit(1)
    logger.info("Temporary credentials successfully generated")
    logger.info(expire.strftime("New credentials will expire on %d/%m/%Y at %X %Z"))
    try:
        access_key_age = aws_credentials.get_access_key_age()
    except NoAccessKeyReturnedFromAws:
        logger.error("No access key was returned from AWS for user")
        exit(1)
    update = None
    if (access_key_age and access_key_age > ACCESS_KEY_AGE_LIMIT_DAYS) or force:
        if not force:
            logger.info(f"\nLooks like your access key is {access_key_age} days old.")
            update = click.confirm("Would you like to update your access keys now?")
        if force:
            update = click.confirm(
                "Are you sure you want to update your non-MFA access keys?"
            )
        if not update:
            logger.info("Not updating non-MFA access keys")
            return
        try:
            aws_credentials.update_access_keys()
        except NoAccessKeyReturnedFromAws:
            logger.error(
                "A local access key could not be found within AWS, and so could not be replaced.\n Please ensure the local access keys exist for your user in AWS before attempting an update."
            )
            exit(1)
        except CouldNotCreateAwsAccessKey:
            logger.error(
                "An error occurred when attempting to create a new access key",
                exc_info=1,
            )
            exit(1)
        except CouldNotDeleteAwsAccessKey as e:
            logger.error(
                "An error occured when attempting to delete an access key", exc_info=1
            )
        logger.info("Non-MFA access keys have been successfully replaced")


if __name__ == "__main__":
    main()
