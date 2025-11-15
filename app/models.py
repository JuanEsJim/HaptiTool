from sqlalchemy import Column, Integer, Float, String, Boolean, ForeignKey, BigInteger, Text, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.orm import declarative_base
from .database import Base
from datetime import datetime, timezone

class Rol(Base):
    __tablename__ = "rol"
    rol_id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String(50), nullable=False)

class Usuario(Base):
    __tablename__ = "usuario"
    usuario_id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    rol_id = Column(Integer, ForeignKey("rol.rol_id"), nullable=False)
    rol = relationship("Rol")

class SesionCaptura(Base):
    __tablename__ = "sesioncaptura"
    sesion_id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey("usuario.usuario_id"), nullable=False)
    fecha = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    descripcion = Column(Text)
    usuario = relationship("Usuario")

class ArchivoMocap(Base):
    __tablename__ = "archivomocap"
    archivo_id = Column(Integer, primary_key=True, index=True)
    sesion_id = Column(Integer, ForeignKey("sesioncaptura.sesion_id"), nullable=False)
    nombre_archivo = Column(String(255), nullable=False)
    ruta_archivo = Column(Text, nullable=False)
    fecha_subida = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    sesion = relationship("SesionCaptura")

class Frame(Base):
    __tablename__ = "frame"
    frame_id = Column(Integer, primary_key=True, index=True)
    sesion_id = Column(Integer, ForeignKey("sesioncaptura.sesion_id"), nullable=False)
    frame_number = Column(Integer, nullable=False)
    timestamp_ms = Column(BigInteger, nullable=False)
    sesion = relationship("SesionCaptura")

class Segmento(Base):
    __tablename__ = "segmento"
    segmento_id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String(100), nullable=False)

class Cinematica(Base):
    __tablename__ = "cinematica"
    cinematica_id = Column(Integer, primary_key=True, index=True)
    frame_id = Column(Integer, ForeignKey("frame.frame_id", ondelete="CASCADE"), nullable=False)
    segmento_id = Column(Integer, ForeignKey("segmento.segmento_id"), nullable=False)
    pos_x = Column(Float)
    pos_y = Column(Float)
    pos_z = Column(Float)
    rot_w = Column(Float)
    rot_x = Column(Float)
    rot_y = Column(Float)
    rot_z = Column(Float)
    frame = relationship("Frame")
    segmento = relationship("Segmento")

class AnguloArticular(Base):
    __tablename__ = "anguloarticular"
    angulo_id = Column(Integer, primary_key=True, index=True)
    frame_id = Column(Integer, ForeignKey("frame.frame_id", ondelete="CASCADE"), nullable=False)
    joint_name = Column(String(100), nullable=False)
    angle = Column(Float)
    angular_v = Column(Float)
    angular_acc = Column(Float)
    frame = relationship("Frame")

class Contacto(Base):
    __tablename__ = "contacto"
    contacto_id = Column(Integer, primary_key=True, index=True)
    frame_id = Column(Integer, ForeignKey("frame.frame_id", ondelete="CASCADE"), nullable=False)
    left_foot_contact = Column(Boolean)
    right_foot_contact = Column(Boolean)
    frame = relationship("Frame")
class Tokens(Base):
    __tablename__ = "tokens"
    token_id = Column(Integer, primary_key=True, index=True)
    access_token = Column(String, unique=True, index=True)
    usuario_id = Column(Integer, ForeignKey("usuario.usuario_id"))
    usuario = relationship("Usuario")

class log_sesion_user(Base):
    __tablename__ = "log_sesion_user"
    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey("usuario.usuario_id"), nullable=False)
    login_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    logout_time = Column(DateTime, nullable=True)

class UserLoginCounter(Base):
    __tablename__ = "user_login_counter"
    id = Column(Integer, primary_key=True, default=1)
    count = Column(Integer, default=0)