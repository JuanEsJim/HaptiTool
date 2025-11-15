import httpx
import pytest
from httpx import AsyncClient
from main import app


def test_root(client):
    """Prueba básica del endpoint raíz."""
    response = client.get("/")
    assert response.status_code == 200
    assert "Hello World" in response.text 

def test_login(client):
    """Prueba del endpoint de login (ajusta según tu modelo)."""
    response = client.post("/login", json={"email": "admin@example.com", "password": "password123"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data



@pytest.mark.asyncio
async def test_upload_csv():
    """Prueba asincrónica del endpoint de subida de CSV."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
      
        csv_content = "frame_number,frame_timestamp,hips.position.x\n1,100,1.0"
        files = {"file": ("test.csv", csv_content, "text/csv")}
        response = await ac.post("/upload_csv/", files=files)
        assert response.status_code == 200
        data = response.json()
        assert "archivo_id" in data



@pytest.mark.asyncio
async def test_get_users():
    """Prueba con httpx para un endpoint protegido."""
    async with httpx.AsyncClient() as client:
       
        headers = {"Authorization": "Bearer test_token_1234567890"}
        response = await client.get("http://127.0.0.1:8000/admin/users/", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)