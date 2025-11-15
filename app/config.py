
import os
from pydantic_settings import BaseSettings, SettingsConfigDict # Importa SettingsConfigDict

class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str = "supersecret"
    DEBUG: bool = True

    
    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(__file__), ".env"),
        env_file_encoding="utf-8"
    )

settings = Settings()