import os
from sys import exit

from invoke import task


@task()
def black(c, fix=False):
    """
    Run python black
    --fix : run the auto-fixer
    """
    c.run(f"black {'--check ' if not fix else ''}.")


@task()
def isort(c, fix=False):
    """
    Run isort
    --fix : run the auto-fixer
    """
    c.run(f"isort --profile black {'--check ' if not fix else ''} ./aws_mfa ./tests")


@task()
def ssort(c, fix=False):
    """
    Run ssort
    --fix : run the auto-fixer
    """
    c.run(f"ssort {'--check ' if not fix else ''}  ./aws_mfa ./tests")


@task(black, isort, ssort)
def lint(c):
    """
    Run all lint commands
    """
    print(
        """
        \033[0;32m==========================================================
        \033[0;32mNo Issues! More effective at de-linting than Scotch-Brite!
        \033[0;32m==========================================================\033[0m
    """
    )


@task(aliases=["format"])
def prettify(c):
    """
    Run the auto-formatter
    """
    isort(c, fix=True)
    ssort(c, fix=True)
    black(c, fix=True)


@task
def typecheck(c):
    """
    Run python mypy
    """
    c.run("mypy aws_mfa tests --config-file=mypy.ini")


@task(
    help={
        "k": "You can use the -k command line option to specify an expression which implements a substring match on the test names",
        "junitxml": "Path to save jUnit xml test files to",
    },
)
def test(c, k=None, junitxml=None):
    """
    Run tests
    """
    c.run(
        f"python -m pytest -v --log-cli-level=INFO {f'--junitxml={junitxml}' if junitxml else ''} ./tests/ --color=yes {f'-k {k}' if k else ''}"
    )


@task
def run(c):
    """
    Starts the local uvicorn webserver (for FastAPI)
    """
    c.run("uvicorn aws_mfa.main:app --reload", pty=True)


@task()
def deploy(c, stage=None):
    """
    Run the serverless deploy
    --stage : stage to deploy to
    """
    if not stage:
        print("must supply a stage, one of dev, staging, prod")
        return

    c.run(f"./node_modules/serverless/bin/serverless.js deploy --stage {stage}")


@task(aliases=["shutdown"])
def remove(c, stage=None, force=False):
    """
    Run the serverless remove. This will shut down the service. Make sure it can be deprecated before executing.
    --stage : stage to deploy to
    """
    protected_branches = ["prod", "production", "staging"]
    if not stage:
        print("must supply a stage with --stage")
        print("this can be custom stage or one of dev, staging, prod")
        return
    else:
        clean_stage = stage.strip()
        print(f"Removing stage {clean_stage}")
        if clean_stage in protected_branches:
            if not force:
                prompt = input(
                    f"{clean_stage} is a protected branch. Please confirm you want to remove it [yes/No]: "
                )
                if prompt.strip() != "yes":
                    print("Confirmation failed. Exiting...")
                    exit(1)

    c.run(f"./node_modules/serverless/bin/serverless.js remove --stage {clean_stage}")
