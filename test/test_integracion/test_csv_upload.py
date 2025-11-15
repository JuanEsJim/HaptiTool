import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.models import Usuario, SesionCaptura, ArchivoMocap
from app.main import app
import io

def test_upload_csv_success(client: TestClient, auth_header: dict, test_db: Session): 
    """
    Prueba que el endpoint /upload_csv/ suba un archivo CSV correctamente con token válido.
    """
   
    csv_content = """frame_number,frame_timestamp,hips.position.x,hips.position.y,hips.position.z
1,100,1.0,2.0,3.0
2,200,1.1,2.1,3.1
"""
    csv_file = ("test_data.csv", io.BytesIO(csv_content.encode()), "text/csv")

   
    response = client.post("/upload_csv/", files={"file": csv_file}, headers=auth_header)

    
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "archivo_id" in data
    assert "sesion_id" in data
    assert "frames_insertados" in data
    assert "segmentos" in data
    assert "articulaciones" in data

    archivo_id = data["archivo_id"]
    sesion_id = data["sesion_id"]

    archivo_db = test_db.query(ArchivoMocap).filter(ArchivoMocap.archivo_id == archivo_id).first() 
    assert archivo_db is not None
    assert archivo_db.sesion_id == sesion_id

    sesion_db = test_db.query(SesionCaptura).filter(SesionCaptura.sesion_id == sesion_id).first()
    assert sesion_db is not None

   


def test_upload_csv_unauthorized(client: TestClient):
    """
    Prueba que el endpoint /upload_csv/ devuelva 401 sin token de autorización.
    """
   
    csv_content = """frame_number,frame_timestamp,hips.position.x
1,100,1.0
"""
    csv_file = ("test_data.csv", io.BytesIO(csv_content.encode()), "text/csv")

    
    response = client.post("/upload_csv/", files={"file": csv_file})

   
    assert response.status_code == 401


def test_upload_csv_invalid_file_type(client: TestClient, auth_header: dict):
    """
    Prueba que el endpoint /upload_csv/ devuelva un error si se sube un archivo no CSV.
    """
   
    txt_content = "Esto no es un CSV."
    txt_file = ("archivo.txt", io.BytesIO(txt_content.encode()), "text/plain")

   
    response = client.post("/upload_csv/", files={"file": txt_file}, headers=auth_header)


    assert response.status_code == 500
