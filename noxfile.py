import nox

nox.options.default_venv_backend = "uv"


@nox.session(python=["3.10", "3.11", "3.12", "3.13", "3.14"])
def tests(session: nox.Session) -> None:
    session.install("-e", ".[django]", "--group", "dev")
    session.run("pytest", *session.posargs)


@nox.session
def lint(session: nox.Session) -> None:
    session.install("ruff")
    session.run("ruff", "check", "src/", "tests/")
    session.run("ruff", "format", "--check", "src/", "tests/")
