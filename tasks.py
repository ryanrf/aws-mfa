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
    c.run(f"isort --profile black {'--check ' if not fix else ''} ./src ./tests")


@task()
def ssort(c, fix=False):
    """
    Run ssort
    --fix : run the auto-fixer
    """
    c.run(f"ssort {'--check ' if not fix else ''}  ./src ./tests")


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
    c.run("mypy src tests --config-file=mypy.ini")


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
