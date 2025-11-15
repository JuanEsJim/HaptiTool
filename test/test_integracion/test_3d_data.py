import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.models import ArchivoMocap, SesionCaptura, Usuario, Rol
from app.main import app
import json



def test_get_3d_data_success(client: TestClient, auth_header: dict, test_db: Session): 
    """
    Prueba que el endpoint /data/3d devuelva datos correctamente para un archivo existente y con token válido.
    """
   
    usuario_prueba = test_db.query(Usuario).filter(Usuario.email == "test@example.com").first() 
    assert usuario_prueba is not None, "Usuario de prueba no encontrado, verificar fixture create_test_user."

    sesion_prueba = SesionCaptura(
        usuario_id=usuario_prueba.usuario_id,
        descripcion="Sesión de prueba para 3D Data"
    )
    test_db.add(sesion_prueba) 
    test_db.commit() 
    test_db.refresh(sesion_prueba) 

    nombre_archivo_test = "test_data.c3d"
    archivo_prueba = ArchivoMocap(
        sesion_id=sesion_prueba.sesion_id,
        nombre_archivo=nombre_archivo_test,
        ruta_archivo="/path/to/test_data.c3d"
    )
    test_db.add(archivo_prueba) 
    test_db.commit() 
    test_db.refresh(archivo_prueba) 

   
    response = client.get(f"/data/3d?nombre_archivo={nombre_archivo_test}", headers=auth_header)

    
    print(f"DEBUG: /data/3d response status: {response.status_code}")
    print(f"DEBUG: /data/3d response body: {response.text}")

    assert response.status_code == 200, f"Esperaba 200, obtuve {response.status_code}. Detalles: {response.text}"
    data = response.json()
    assert "frames" in data
    assert "file_type" in data
    assert data["file_type"] == "c3d"



def test_get_3d_data_file_not_found(client: TestClient, auth_header: dict):
    """
    Prueba que el endpoint /data/3d devuelva 404 si el archivo no existe.
    """
    
    response = client.get("/data/3d?nombre_archivo=archivo_inexistente.c3d", headers=auth_header)

    assert response.status_code == 404

def test_get_3d_data_unauthorized(client: TestClient):
    """
    Prueba que el endpoint /data/3d devuelva 401 sin token de autorización.
    """
    
    response = client.get("/data/3d?nombre_archivo=test.c3d") 

   
    assert response.status_code == 401