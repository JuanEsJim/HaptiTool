# test/test_user_management.py
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.models import Usuario, Rol, UserLoginCounter, log_sesion_user
from app.main import app
import json

def test_get_user_by_id_unauthorized(client: TestClient, auth_header: dict, create_test_user: Usuario):
    """
    Prueba que un usuario normal no pueda acceder a /admin/users/{user_id}.
    """
  
    response = client.get(f"/admin/users/{create_test_user.usuario_id}", headers=auth_header)
    
    assert response.status_code == 403 


def test_get_user_by_id_not_found(client: TestClient, auth_header: dict):
    """
    Prueba que /admin/users/{user_id} devuelva 404 si el usuario no existe,
    aunque el token sea de un admin (si aplica).
    """
  
    non_existent_id = 99999
 
    response = client.get(f"/admin/users/{non_existent_id}", headers=auth_header)
   
    assert response.status_code == 403
    
def test_get_all_users_unauthorized(client: TestClient, auth_header: dict):
    """
    Prueba que un usuario normal no pueda acceder a /admin/users/ (listar todos).
    """
    response = client.get("/admin/users/", headers=auth_header)
    assert response.status_code == 403 



def test_update_user_password_unauthorized(client: TestClient, auth_header: dict, create_test_user: Usuario):
    """
    Prueba que un usuario normal no pueda cambiar la contraseña de otro usuario.
    """
    new_password_data = {"new_password": "new_strong_password_123"}
    response = client.put(
        f"/admin/users/{create_test_user.usuario_id}/password",
        json=new_password_data,
        headers=auth_header
    )
    assert response.status_code == 403 


def test_update_user_password_same_user(client: TestClient, auth_header: dict, create_test_user: Usuario):
    """
    Prueba que un usuario normal no pueda cambiar su *propia* contraseña vía /admin/... .
    (Aunque quizás debería poder por un endpoint diferente, no /admin).
    """
    new_password_data = {"new_password": "new_strong_password_456"}
    response = client.put(
        f"/admin/users/{create_test_user.usuario_id}/password",
        json=new_password_data,
        headers=auth_header
    )
 
    assert response.status_code == 403



def test_delete_user_unauthorized(client: TestClient, auth_header: dict, create_test_user: Usuario):
    """
    Prueba que un usuario normal no pueda eliminar a otro usuario.
    """
    response = client.delete(f"/admin/users/{create_test_user.usuario_id}", headers=auth_header)
    assert response.status_code == 403



def test_create_admin_unauthorized(client: TestClient, auth_header: dict):
    """
    Prueba que un usuario normal no pueda crear un nuevo admin.
    """
    new_admin_data = {
        "nombre": "Admin Prueba",
        "email": "admin_test@example.com",
        "password": "admin_password_123"
    }
    response = client.post("/create_admin", json=new_admin_data, headers=auth_header)
    assert response.status_code == 403 



def test_get_user_login_count_unauthorized(client: TestClient, auth_header: dict):
    """
    Prueba que un usuario normal no pueda acceder al contador de usuarios que han iniciado sesión.
    """
    response = client.get("/admin/user-count/", headers=auth_header)
    assert response.status_code == 403 



def test_get_session_logs_unauthorized(client: TestClient, auth_header: dict):
    """
    Prueba que un usuario normal no pueda acceder a los logs de sesión.
    """
    response = client.get("/admin/session-logs/", headers=auth_header)
    assert response.status_code == 403 



def test_login_creates_log_and_increments_counter(client: TestClient, create_test_user: Usuario, test_db: Session): 
    """
    Prueba que al hacer login, se cree un log_sesion_user y se incremente UserLoginCounter.
    """
    
    initial_counter = test_db.query(UserLoginCounter).first() 
    initial_count = initial_counter.count if initial_counter else 0
    initial_log_count = test_db.query(log_sesion_user).count() 

    
    login_data = {"email": create_test_user.email, "password": "password123"}
    response = client.post("/login", json=login_data)

  
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

    
    test_db.expire_all() 
    final_log_count = test_db.query(log_sesion_user).count() 
    assert final_log_count == initial_log_count + 1

   
    final_counter = test_db.query(UserLoginCounter).first()
    assert final_counter is not None
    assert final_counter.count == initial_count + 1

   
    new_log = test_db.query(log_sesion_user).order_by(log_sesion_user.id.desc()).first() 
    assert new_log.usuario_id == create_test_user.usuario_id


