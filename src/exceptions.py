class AwsCredentialsMissingSection(Exception):
    pass


class FailedToLoadCredentialsFile(Exception):
    pass


class AwsCredentialsUsingEnvVars(Exception):
    pass


class AwsCredentialsNotFound(Exception):
    pass


class AwsBadCredentials(Exception):
    pass


class AwsCredentialsNoSharedCredentialsFileFound(Exception):
    pass


class NoMfaDeviceFound(Exception):
    pass


class NoAccessKeyReturnedFromAws(Exception):
    pass


class CouldNotCreateAwsAccessKey(Exception):
    pass


class CouldNotDeleteAwsAccessKey(Exception):
    pass


class InvalidTokenCode(Exception):
    pass
