# FastAPI Quick Starter 🚀

This repository serves as a comprehensive template and quick start guide for developing robust FastAPI applications. Whether you're a seasoned developer or just getting started with FastAPI, this template provides a solid foundation and streamlines the development process, allowing you to focus more on building your application's features.

## Getting Started 🛠️
**Requirements**:
- [Python](https://www.python.org/) version 3.10 or higher
- [Docker](https://www.docker.com/)

**Setting Up the Environment**:
1. Copy the contents of [.env.local](./.env.local) to a file named `.env` (modify the variables if needed) in the root directory.
2. Create a virtual environment by running the following script:
    ```bash
    python3 -m venv venv
    ```
    Note: If you only have Python 3.x installed, the command above may fail. In such cases, run:
    ```bash
    python -m venv venv
    ```
    This will create a directory called `venv` where the binaries will be installed.
3. Activate the virtual environment:
    ```bash
    source venv/bin/activate
    ```
4. Install [Poetry](https://python-poetry.org/):
    ```bash
    poetry install
    ```
5. Build the [`backend` image](./Dockerfile):
    ```bash
    docker compose build
    ```
6. Generate the initial [Alembic](https://pypi.org/project/alembic/) migration:
    ```bash
        docker compose run --rm --entrypoint "sh -c" backend "alembic revision --autogenerate -m 'initial migration'"
    ```
7. Keep the [Alembic](https://pypi.org/project/alembic/) migrations head updated:
    ```bash
        docker compose run --rm --entrypoint "sh -c" backend "alembic upgrade head"
    ```
8. Run [initialize script](./initialize.py):
    ```bash
        docker compose run --rm --entrypoint "sh -c" backend "python3 initialize.py"
    ```
    - The script will create a new user (if no users created) with: <a id="creating-credentials"></a>
        - E-mail: `admin@admin.com`
        - Password: `password`
        - Role: `admin`
9. Start the [`backend` container](./docker-compose.yml#L9):
    ```bash
    docker compose up -d backend
    ```
    **Note 1**: The [`backend` container](./docker-compose.yml#L9) depends on the [`database` container](./docker-compose.yml#L55), which will be pulled and started automatically.
    
    **Note 2**: The `-d` flag detaches the container from the terminal, allowing you to close the terminal without stopping the container.
    
    **Note 3**: If an error occurs stating that something is running on port 80, you can change the `API_PORT` variable in your `.env` file.

10. The API should now be up and running on localhost. You can access the autogenerated Swagger documentation at [http://localhost/docs](http://localhost/docs).
    **Note**: To test the authentication process, access the authentication endpoint directly or via Swagger UI. Utilize the credentials generated in step 8 to authenticate the requests.

## Project Structure 📁
**Root (./)**
- This directory contains the configuration for the app's environment, using [Poetry](https://python-poetry.org/) as a dependency manager, [Docker](https://www.docker.com/) for containerization, [SQLAlchemy](https://www.sqlalchemy.org/) as the ORM, and [Alembic](https://pypi.org/project/alembic/) for database migrations.

- **Env files**: `.env.local` stores environment variables for local environments, while `.env.ci` stores variables for CI environments.

- **[Poetry](https://python-poetry.org/)**: Poetry manages dependencies via `pyproject.toml` and `poetry.lock`. Avoid manually editing `poetry.lock`, as it's updated automatically with `poetry` commands.

**Database**
- Configuration for [Alembic](https://pypi.org/project/alembic/) resides here.

**src**
- The heart of the application!

**src/main.py**
- Instantiates FastAPI and includes all routers.

**src/config**
- Configuration files, including [`settings.py`](./src/config/settings.py) for environment variables.

**src/core**
- Houses modules external to FastAPI, such as [`database.py`](./src/core/database.py) for PostgreSQL connections, [`email.py`](./src/core/email.py) for configuring email servers, and [`dependencies.py`](./src/core/dependencies.py) for dependency injection.

**src/managers**
- Handles application logic and database transactions.

**src/models**
- Contains data models, categorized into `pydantic` (inherited from Pydantic) and `orm` (SQLAlchemy models).

**src/routers**
- Includes all routers. Also contains an `email_templates` folder with [Jinja2 templates](https://jinja.palletsprojects.com/en/3.1.x/templates/) for API-sent emails.

**src/tests**
- Crucial for project integrity, this directory houses unit tests.
- [`main conftest.py`](./src/tests/conftest.py) instantiates a `TestClient` with all necessary mocks.
- `src/tests/core` tests essential API functionalities, with a current focus on health checks.
- `src/tests/models` tests models and ORM functionality.
- `src/tests/routers` contains the bulk of API router tests.

## Extending the API ➕
- When adding a new router file to `src/routers`, ensure it's added to [`main.py`](./src/main.py) for availability in the API.

## Modifying ORM Models 💾
- When adding a new data model to `src/models/orm`, import it into the [Alembic environment](./database/env.py#L20) to map the model and perform migrations.
- After changing or adding a data model, generate a migration:
    ```bash
    alembic revision --autogenerate -m "(description of changes)"
    ```
    Review the generated migration file in `database/versions` to ensure it matches expectations. Keep the head updated with:
    ```bash
    docker compose run --rm --entrypoint "sh -c" backend 'alembic upgrade head'
    ```

## Running Tests 🧪
- To run tests, use the following script:
    ```bash
    docker compose run --rm --entrypoint "sh -c" backend 'pytest'
    ```

    **Note**: Adjust the command to suit your testing preferences, such as:
    ```bash
    docker compose run --rm --entrypoint "sh -c" backend 'pytest -vvv'
    ```
    for increased verbosity.

## Using Poetry for Dependency Management 📦

Poetry is a powerful dependency management tool for Python projects. It simplifies the process of managing dependencies, packaging, and publishing your project.

### Installation
If you haven't installed Poetry yet, you can do so using pip:

```bash
pip install poetry
```

### Adding Dependencies
To add dependencies to your project, use the `add` command followed by the package name and optionally the version:

```bash
poetry add package_name
```

For example, to add FastAPI:

```bash
poetry add fastapi
```

### Updating Dependencies
To update dependencies to their latest compatible version, use the `update` command:

```bash
poetry update
```

### Removing Dependencies
To remove a dependency from your project, use the `remove` command followed by the package name:

```bash
poetry remove package_name
```

### Installing Dependencies
After adding or updating dependencies, you need to install them:

```bash
poetry install
```

This command will create a virtual environment and install all dependencies specified in your `pyproject.toml` file.

### Running Scripts
You can define custom scripts in your `pyproject.toml` file under the `[tool.poetry.scripts]` section. To run a script, use the `run` command followed by the script name:

```bash
poetry run script_name
```

For example, if you have a script named `my_script`:

```bash
poetry run my_script
```

### Generating Lock File
Poetry generates a lock file (`poetry.lock`) to ensure deterministic builds. To regenerate the lock file, use the `lock` command:

```bash
poetry lock
```

### More Information
For more information and advanced usage of Poetry, refer to the [official documentation](https://python-poetry.org/docs/).


## Implemented Features 🎉
The API already includes endpoints for various operations:
1. **Direct User Creation**:
    - Utilize the [`create_user` route](./src/routers/user.py#L21) in the user router to create a user by providing the necessary information in the request body.
2. **User Invitation Flow**:
    - An implemented flow where users are invited via email, receive an invitation link, submit their new credentials, and are subsequently created. See [here](./src/routers/user.py#L30) and [here](./src/routers/user.py#L53).
3. **User Authorization/Authentication Flow**:
    - After creation, users can obtain an `OAuth2 Bearer Token` by submitting their email and password, allowing them to perform authorized requests. See [here](./src/routers/user.py#L62) and [here](./src/routers/user.py#L82).
4. **Role-Based Access Control (RBAC) with Scopes**:
- Implemented RBAC ensures secure access control to resources based on user roles and scopes. Users are assigned specific permissions (scopes) that dictate their access level within the system, enhancing security and enforcing authorization policies. See [here](./src/core/dependencies.py#L62) and [here](./src/core/utils.py#L55).

### Connect and Follow
I hope this template proves useful for your applications! Don't forget to follow me here on [GitHub](https://github.com/matheushss1) and connect with me on [LinkedIn](https://www.linkedin.com/in/eng-matheus-henrique/).
