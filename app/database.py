from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from config import settings

# Crear engine con la URL de la BD desde .env
engine = create_engine(settings.DATABASE_URL, echo=settings.DEBUG)

# Sesiones
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base para modelos
Base = declarative_base()
