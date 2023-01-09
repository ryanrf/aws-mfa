#!/usr/bin/env python
import click
import logging
from sys import stdout
from .aws_credentials import AwsCredentials

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
    aws_credentials.update_credentials(
        aws_credentials.load_creds_file(),
        aws_credentials.get_credentials(duration, token),
    )


if __name__ == "__main__":
    main()
