
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.models import Usuario, SesionCaptura, ArchivoMocap, Frame, Cinematica
from app.main import app
import io
import os

UPLOADS_DIR = "uploads"
DOWNLOADS_DIR = "downloads"



def test_list_files_success(client: TestClient, auth_header: dict, test_db: Session): 
    """
    Prueba que el endpoint /lista_archivos/ devuelva una lista de archivos.
    """
    
    usuario_prueba = test_db.query(Usuario).filter(Usuario.email == "test@example.com").first() 
    assert usuario_prueba is not None

    sesion_prueba = SesionCaptura(usuario_id=usuario_prueba.usuario_id, descripcion="Sesión para listar archivos")
    test_db.add(sesion_prueba) 
    test_db.commit() 
    test_db.refresh(sesion_prueba) 

    nombre_archivo_test = "test_list_files.c3d"
    archivo_prueba = ArchivoMocap(sesion_id=sesion_prueba.sesion_id, nombre_archivo=nombre_archivo_test, ruta_archivo=f"/path/to/{nombre_archivo_test}")
    test_db.add(archivo_prueba) 
    test_db.commit() 
    test_db.refresh(archivo_prueba) 

    
    response = client.get("/lista_archivos/", headers=auth_header)

    
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert nombre_archivo_test in data


def test_list_files_unauthorized(client: TestClient):
    """
    Prueba que /lista_archivos/ devuelva 401 sin token.
    """
    response = client.get("/lista_archivos/")
    assert response.status_code == 401


def test_download_file_success(client: TestClient, auth_header: dict, test_db: Session):
    """
    Prueba que el endpoint /download/{filename} devuelva un archivo existente.
    """
    
    usuario_prueba = test_db.query(Usuario).filter(Usuario.email == "test@example.com").first() 
    assert usuario_prueba is not None

    sesion_prueba = SesionCaptura(usuario_id=usuario_prueba.usuario_id, descripcion="Sesión para descargar archivo")
    test_db.add(sesion_prueba) 
    test_db.commit()
    test_db.refresh(sesion_prueba) 

    nombre_archivo_test = "test_download.csv"
    ruta_archivo_test = os.path.join(DOWNLOADS_DIR, nombre_archivo_test)
    os.makedirs(DOWNLOADS_DIR, exist_ok=True)
    with open(ruta_archivo_test, "w") as f:
        f.write("frame_number,frame_timestamp,hips.position.x\n1,100,1.0\n")

    archivo_prueba = ArchivoMocap(sesion_id=sesion_prueba.sesion_id, nombre_archivo=nombre_archivo_test, ruta_archivo=ruta_archivo_test)
    test_db.add(archivo_prueba) 
    test_db.commit() 
    test_db.refresh(archivo_prueba) 

    
    response = client.get(f"/download/{nombre_archivo_test}", headers=auth_header)

  
    assert response.status_code == 200

  
    if os.path.exists(ruta_archivo_test):
        os.remove(ruta_archivo_test)


def test_download_file_not_found(client: TestClient, auth_header: dict):
    """
    Prueba que /download/{filename} devuelva 404 si el archivo no existe en la DB.
    """
    non_existent_filename = "archivo_inexistente.c3d"
    response = client.get(f"/download/{non_existent_filename}", headers=auth_header)
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    assert "no encontrado" in data["detail"]


def test_download_file_not_found_physical(client: TestClient, auth_header: dict, test_db: Session): # <-- Cambiado 'db' por 'test_db'
    """
    Prueba que /download/{filename} devuelva 404 si el archivo existe en la DB pero no físicamente.
    """
   
    usuario_prueba = test_db.query(Usuario).filter(Usuario.email == "test@example.com").first() 
    assert usuario_prueba is not None

    sesion_prueba = SesionCaptura(usuario_id=usuario_prueba.usuario_id, descripcion="Sesión para descargar archivo físico inexistente")
    test_db.add(sesion_prueba) 
    test_db.commit()
    test_db.refresh(sesion_prueba)

    nombre_archivo_test = "test_physical_not_found.csv"
    ruta_archivo_test = f"/path/to/{nombre_archivo_test}" 

    archivo_prueba = ArchivoMocap(sesion_id=sesion_prueba.sesion_id, nombre_archivo=nombre_archivo_test, ruta_archivo=ruta_archivo_test)
    test_db.add(archivo_prueba) 
    test_db.commit() 
    test_db.refresh(archivo_prueba) 

    
    response = client.get(f"/download/{nombre_archivo_test}", headers=auth_header)


    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    assert "no encontrado en el sistema" in data["detail"] 


def test_download_file_unauthorized(client: TestClient):
    """
    Prueba que /download/{filename} devuelva 401 sin token.
    """
    response = client.get("/download/somefile.csv")
    assert response.status_code == 401



def test_delete_file_unauthorized(client: TestClient):
    """
    Prueba que DELETE /archivo/{nombre_archivo} devuelva 401 sin token.
    """
    response = client.delete("/archivo/archivo_test.c3d")
    assert response.status_code == 401 



def test_delete_file_not_found_unauthorized(client: TestClient, auth_header: dict):
    """
    Prueba que DELETE /archivo/{nombre_archivo} devuelva 403 si el usuario no es admin,
    incluso si el archivo no existe.
    """
    non_existent_filename = "archivo_para_borrar_inexistente.c3d"
   
    response = client.delete(f"/archivo/{non_existent_filename}", headers=auth_header)
    assert response.status_code == 403
def test_update_file_unauthorized(client: TestClient):
    """
    Prueba que PUT /archivo/{nombre_archivo} devuelva 401 sin token.
    """
    csv_content = """frame_number,frame_timestamp,hips.position.x\n1,100,1.0\n"""
    csv_file = ("test_update.csv", io.BytesIO(csv_content.encode()), "text/csv")
    response = client.put("/archivo/archivo_inexistente_para_update.c3d", files={"file": csv_file})
    assert response.status_code == 401 



def test_update_file_not_found_unauthorized(client: TestClient, auth_header: dict):
    """
    Prueba que PUT /archivo/{nombre_archivo} devuelva 403 si el usuario no es admin,
    incluso si el archivo no existe.
    """
    csv_content = """frame_number,frame_timestamp,hips.position.x\n1,100,1.0\n"""
    csv_file = ("test_update.csv", io.BytesIO(csv_content.encode()), "text/csv")
    non_existent_filename = "archivo_para_update_inexistente.c3d"
    response = client.put(f"/archivo/{non_existent_filename}", files={"file": csv_file}, headers=auth_header)
    assert response.status_code == 403 


def test_update_file_wrong_type(client: TestClient, auth_header: dict, test_db: Session): 
    """
    Prueba que PUT /archivo/{nombre_archivo} devuelva 403 si el usuario no es admin,
    incluso si se sube un archivo con extensión incorrecta.
    """
    
    usuario_prueba = test_db.query(Usuario).filter(Usuario.email == "test@example.com").first() 
    assert usuario_prueba is not None

    sesion_prueba = SesionCaptura(usuario_id=usuario_prueba.usuario_id, descripcion="Sesión para actualizar archivo")
    test_db.add(sesion_prueba)
    test_db.commit() 
    test_db.refresh(sesion_prueba) 

    nombre_archivo_existente = "test_update_target.c3d" 
    archivo_prueba = ArchivoMocap(sesion_id=sesion_prueba.sesion_id, nombre_archivo=nombre_archivo_existente, ruta_archivo=f"/path/to/{nombre_archivo_existente}")
    test_db.add(archivo_prueba) 
    test_db.commit() 
    test_db.refresh(archivo_prueba) 
    csv_content = """frame_number,frame_timestamp,hips.position.x\n1,100,1.0\n"""
    csv_file = ("archivo_para_update.csv", io.BytesIO(csv_content.encode()), "text/csv")

  
    response = client.put(f"/archivo/{nombre_archivo_existente}", files={"file": csv_file}, headers=auth_header)

   
    assert response.status_code == 403 

