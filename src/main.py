from fastapi import Depends, FastAPI
from src.config.settings import Settings
from src.core.dependencies import get_settings
from src.core.security import oauth2_scheme  # noqa
from src.routers.user import router as user_router

settings = get_settings()

app = FastAPI(debug=settings.API_DEBUG, title=settings.API_NAME)


@app.get("/health-check")
async def health_check(settings: Settings = Depends(get_settings)):
    return {"data": f"{settings.API_NAME} is working as expected"}


app.include_router(user_router)
