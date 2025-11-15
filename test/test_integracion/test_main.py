
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.main import app
from app.models import Usuario

def test_read_main(client):
    """Prueba básica del endpoint raíz."""
    response = client.get("/")

def test_login(client, create_test_user):
    """Prueba el endpoint de login."""
    response = client.post("/login", json={"email": "test@example.com", "password": "password123"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["access_token"] is not None

def test_protected_endpoint_without_token(client):
    """Prueba que un endpoint protegido falle sin token."""
    response = client.get("/users/me")
    assert response.status_code == 401

def test_protected_endpoint_with_token(client, auth_header):
    """Prueba que un endpoint protegido funcione con token."""
    response = client.get("/users/me", headers=auth_header)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"

