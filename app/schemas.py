
from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class UsuarioBase(BaseModel):
    nombre: str
    email: str

class UsuarioCreate(UsuarioBase):
    password: str
    rol_id: int

class RolResponse(BaseModel):
    rol_id: int
    nombre: str

    class Config:
        from_attributes = True  
        
class UsuarioResponse(UsuarioBase):
    usuario_id: int
    rol_id: int
    rol: Optional[RolResponse] = None

    class Config:
         orm_mode = True

class SesionResponse(BaseModel):
    sesion_id: int
    descripcion: str
    fecha: datetime
      
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    
class ArchivoDetalle(BaseModel):
    nombre_archivo: str
    usuario_nombre: str
    
class UserLogin(BaseModel):
    email: str
    password: str
    
