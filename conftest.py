import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool 
from sqlalchemy.orm import sessionmaker
from app.database import Base  
from app.main import get_db 
from app.main import app as original_app  
from passlib.context import CryptContext
import os
from app.models import Rol 

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,

    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    echo=False 
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Crea las tablas en la base de datos de prueba antes de ejecutar las pruebas."""
   
    print("DEBUG: setup_database - Tablas antes de create_all:", list(Base.metadata.tables.keys()))
    Base.metadata.create_all(bind=engine) 
    print("DEBUG: setup_database - Tablas creadas en engine SQLite (StaticPool).") 
    yield
    Base.metadata.drop_all(bind=engine)
    print("DEBUG: setup_database - Tablas eliminadas.") 



@pytest.fixture(scope="function")
def test_db(setup_database): 
    """Crea una sesión de base de datos para cada prueba."""
    db = TestingSessionLocal()
    try:
        
        roles_iniciales = ["usuario", "admin", "super_admin"]
        for nombre_rol in roles_iniciales:
            rol_existente = db.query(Rol).filter(Rol.nombre == nombre_rol).first()
            if not rol_existente:
                nuevo_rol = Rol(nombre=nombre_rol)
                db.add(nuevo_rol)

        db.commit()
        print("DEBUG: test_db - Roles iniciales creados/verificados.") 

        yield db

    finally:
        db.rollback()
        db.close()
        print("DEBUG: test_db - Rollback y close realizados.") 



@pytest.fixture(scope="function")
def create_test_user(test_db):
    """Crea un usuario de prueba para las pruebas."""
    from app.models import Usuario, Rol

    
    hashed_password = pwd_context.hash("password123")

    
    rol_usuario = test_db.query(Rol).filter(Rol.nombre == "usuario").first()
    if not rol_usuario:
       
        raise RuntimeError("Rol 'usuario' no encontrado en la base de datos de prueba. Revisa setup_database y test_db.")


    existing_user = test_db.query(Usuario).filter(Usuario.email == "test@example.com").first()
    if existing_user:
        print("DEBUG: create_test_user - Usuario de prueba ya existente en esta sesión de prueba, devolviéndolo.")
        return existing_user 
    test_user = Usuario(
        nombre="Usuario Prueba",
        email="test@example.com",
        password_hash=hashed_password,
        rol_id=rol_usuario.rol_id
    )
    test_db.add(test_user)
    test_db.commit()
    test_db.refresh(test_user) 
    print(f"DEBUG: create_test_user - Usuario creado con ID: {test_user.usuario_id}")

    return test_user

@pytest.fixture(scope="function")
def auth_header(client, create_test_user):
    """Obtiene un header de autorización para un usuario de prueba."""
    print("DEBUG: auth_header - Iniciando login para obtener token.")
 
    response = client.post("/login", json={"email": "test@example.com", "password": "password123"})
    print(f"DEBUG: auth_header - Login response status: {response.status_code}")
    print(f"DEBUG: auth_header - Login response body: {response.text}")
    assert response.status_code == 200
    data = response.json()
    token = data["access_token"]
    print(f"DEBUG: auth_header - Token obtenido: {token[:10]}...") 

 
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(scope="function")
def client(test_db):
    """Crea un cliente de prueba para la aplicación FastAPI."""
    print("DEBUG: client - Configurando override para get_db")

    
    def override_get_db():
        try:
           
            yield test_db
           
        finally:
            pass


    app = original_app

    app.dependency_overrides[get_db] = override_get_db

    
    print("DEBUG: client - Creando TestClient")
    with TestClient(app) as c:
        yield c

    
    print("DEBUG: client - Limpiando override de get_db")
    app.dependency_overrides.clear()
