from os import getenv

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Get settings from environment variables
    """

    API_NAME: str = getenv("API_NAME")
    API_DEBUG: bool = getenv("API_DEBUG")
    TIMEOUT: int = getenv("TIMEOUT")
    DB_HOST: str = getenv("DB_HOST")
    DB_USERNAME: str = getenv("DB_USERNAME")
    DB_PASSWORD: str = getenv("DB_PASSWORD")
    DB_DATABASE: str = getenv("DB_DATABASE")
    DB_PORT: int = getenv("DB_PORT")
    SECRET_KEY: str = getenv("SECRET_KEY")
    ALGORITHM: str = getenv("ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = getenv("ACCESS_TOKEN_EXPIRE_MINUTES")
    FRONTEND_URL: str = getenv("FRONTEND_URL")
    MAIL_USERNAME: str = (getenv("MAIL_USERNAME"),)
    MAIL_PASSWORD: str = getenv("MAIL_PASSWORD")
    MAIL_FROM: str = (getenv("MAIL_FROM"),)
    MAIL_PORT: int = (getenv("MAIL_PORT"),)
    MAIL_SERVER: str = (getenv("MAIL_SERVER"),)
    MAIL_FROM_NAME: str = (getenv("MAIL_FROM_NAME"),)
    MAIL_STARTTLS: bool = (getenv("MAIL_STARTTLS"),)
    MAIL_SSL_TLS: bool = (getenv("MAIL_SSL_TLS"),)
    USE_CREDENTIALS: bool = (getenv("USE_CREDENTIALS"),)
    VALIDATE_CERTS: bool = getenv("VALIDATE_CERTS")
