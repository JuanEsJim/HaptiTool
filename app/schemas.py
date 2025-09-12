# schemas.py
from pydantic import BaseModel
from datetime import datetime

class UsuarioBase(BaseModel):
    nombre: str
    email: str

class UsuarioCreate(UsuarioBase):
    password: str
    rol_id: int

class UsuarioResponse(UsuarioBase):
    usuario_id: int
    rol_id: int

    class Config:
        orm_mode = True

class SesionResponse(BaseModel):
    sesion_id: int
    descripcion: str
    fecha: datetime

    class Config:
        orm_mode = True
