#!/bin/bash
alembic upgrade head
if [ ! -f .env ]
then
    source .env
fi
uvicorn src.main:app --host 0.0.0.0 --port ${API_PORT} --reload
exec "$@"