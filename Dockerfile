FROM python:3.11-slim AS env_base

ARG build_environment=production

ENV POETRY_VERSION=1.8.1
ENV POETRY_HOME="/opt/poetry"
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
ENV POETRY_NO_INTERACTION=1
ENV BUILD_ENV=${build_environment}

ENV PATH="$POETRY_HOME/bin:$PATH"

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        # deps for installing poetry
        curl \
        # deps for building python deps
        build-essential \
        # libpq-dev and python-dev are needed to install psycopg2
        libpq-dev \
        # python-dev is no longer available since Debian 11
        python-dev-is-python3

FROM env_base as poetry_base

# install poetry - respects $POETRY_VERSION & $POETRY_HOME
RUN curl -sSL https://install.python-poetry.org | python -

FROM poetry_base as build_base

COPY --from=poetry_base $POETRY_HOME $POETRY_HOME

RUN python -m venv /venv

COPY poetry.lock pyproject.toml ./

RUN . /venv/bin/activate && poetry install $( (test $BUILD_ENV = "production" && echo "--without dev") || echo )


#################################################################################################
# The runtime-stage image
#################################################################################################
# we can use Debian as the base image since the Conda env also includes Python for us.
FROM env_base AS runtime

# Copy /venv from the previous stage:
COPY --from=build_base /venv /venv

# make execuatables available on the path.
ENV PATH="/venv/bin:${PATH}"

# Setup FastAPI
# https://fastapi.tiangolo.com/deployment/docker/#dockerfile

WORKDIR /code

COPY initialize.py entrypoint.sh ./

RUN ["chmod", "+x" , "./entrypoint.sh"]

# Copy the ./src directory inside the /code directory.
# Do this last to leverge docker build caching.
COPY ./src /code/src

EXPOSE $PORT

ENTRYPOINT ["./entrypoint.sh"]
