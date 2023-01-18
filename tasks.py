import os
from sys import exit

from invoke import task
from properly_util_python_private.invoke import (
    black,
    isort,
    ssort,
    lint,
    prettify,
    typecheck,
    test,
)
