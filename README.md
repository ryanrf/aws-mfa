# AWS MFA CLI tool

In order to utilize multi-factor authentication with AWS a session token must be generated and configured for a user. By default the session token will only be valid for 12 hours, so this process needs to be repeated every time. This tool aims to make that process smooth and simple. At this time only a local shared credentials file (e.g. `~/.aws/credentials`) is supported. For more information on setting up a local shared credentials file see [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).


## Installation
The only requirement for this tool is to have [`poetry`](https://python-poetry.org/). If using `pyenv`, please ensure you are using the correct version (specified in the [`.python-version`](./.python-version) file). You may need to select that version before installing `poetry`:
```shell
pyenv install 3.9.13
pyenv global 3.9.13
```

It is recommended to install this as a regular user, but outside of a virtual environment. This tool is installed and added to the user's path to allow the command `aws-mfa` to work from anywhere. To install:
```shell
pip install .
```

## Upgrade
As a python module `aws-mfa` can be upgraded the same as any other python module:
```shell
pip install --upgrade aws-mfa
```
> Or if using poetry
```shell
poetry update aws-mfa
```

## Usage
Once you have a local shared credentials file setup and this tool installed simple run
```shell
aws-mfa -t <token code>
```

If you omit `<token code>` you will be prompted for one.
There is a simple help page available with:
```shell
aws-mfa --help
```
