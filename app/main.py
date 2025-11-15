import ezc3d
from typing import List, Dict, Any
from collections import defaultdict
import tempfile
import os
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status, APIRouter
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import Column, Integer
from passlib.context import CryptContext
import secrets
from datetime import datetime, timezone
from .database import SessionLocal, engine, Base
from .models import AnguloArticular, ArchivoMocap, Cinematica, Contacto, Frame, Segmento, SesionCaptura, UserLoginCounter, Usuario, Tokens, log_sesion_user
from .schemas import UsuarioCreate, UsuarioResponse, UserLogin, Token
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import pandas as pd, io
from datetime import datetime, timezone
from fastapi import HTTPException
from fastapi.responses import FileResponse


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
        
        
app = FastAPI()

# Inicialización del contexto de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Asegurar que las tablas existen en la BD
#Base.metadata.create_all(bind=engine)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)




def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(password: str, hashed_password: str):
    return pwd_context.verify(password, hashed_password)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Buscar el token en la tabla Tokens
    db_token = db.query(Tokens).filter(Tokens.access_token == token).first()
    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    
    user = db.query(Usuario).filter(Usuario.usuario_id == db_token.usuario_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

async def procesar_csv(file: UploadFile, db: Session, current_user: Usuario, sesion_id: int):
    """
    Procesa un archivo CSV y guarda los datos en la base de datos.
    Reutiliza la lógica del endpoint /upload_csv/.
    """
    try:
        # Leer CSV completo
        contents = await file.read()
        df = pd.read_csv(io.StringIO(contents.decode("utf-8")))

        if df.empty:
            raise HTTPException(status_code=400, detail="El archivo CSV está vacío")

        df = df.dropna(how="all").fillna(0)

        # Crear nueva sesión de captura 
        nueva_sesion = db.query(SesionCaptura).filter(SesionCaptura.sesion_id == sesion_id).first()
        if not nueva_sesion:
            raise HTTPException(status_code=404, detail="Sesión no encontrada")

        # Crear registro de archivo
        nuevo_archivo = db.query(ArchivoMocap).filter(ArchivoMocap.sesion_id == sesion_id).first()
        if not nuevo_archivo:
            raise HTTPException(status_code=404, detail="Archivo no encontrado")

        # Detectar columnas
        columnas = df.columns
        segmentos = sorted(set(col.split('.')[0] for col in columnas if ".position" in col or ".rotation" in col))
        articulaciones = sorted(set(col.split('.')[0] for col in columnas if ".angle" in col))
        contactos = [col for col in columnas if ".contact" in col]

        # Crear segmentos si no existen
        segmentos_db = {}
        for seg in segmentos:
            existente = db.query(Segmento).filter_by(nombre=seg).first()
            if not existente:
                nuevo_seg = Segmento(nombre=seg)
                db.add(nuevo_seg)
                db.commit()
                db.refresh(nuevo_seg)
                segmentos_db[seg] = nuevo_seg
            else:
                segmentos_db[seg] = existente

        # Acumuladores para inserción masiva
        frames_bulk = []
        cinematica_bulk = []
        angulos_bulk = []
        contactos_bulk = []

        # Recorrer frames
        for _, row in df.iterrows():
            frame = Frame(
                sesion_id=nueva_sesion.sesion_id,
                frame_number=int(row.get("frame_number", 0)),
                timestamp_ms=int(row.get("frame_timestamp", 0))
            )
            frames_bulk.append(frame)

        # Guardar todos los frames primero
        db.bulk_save_objects(frames_bulk)
        db.commit()

        # Obtener los IDs asignados a los frames
        frames_guardados = (
            db.query(Frame)
            .filter(Frame.sesion_id == nueva_sesion.sesion_id)
            .order_by(Frame.frame_id)
            .all()
        )

        # Generar registros secundarios (cinemática, ángulos, contactos)
        for idx, (_, row) in enumerate(df.iterrows()):
            frame_id = frames_guardados[idx].frame_id

            # Cinemática
            for seg in segmentos:
                cinematica_bulk.append(
                    Cinematica(
                        frame_id=frame_id,
                        segmento_id=segmentos_db[seg].segmento_id,
                        pos_x=float(row.get(f"{seg}.position.x", 0)),
                        pos_y=float(row.get(f"{seg}.position.y", 0)),
                        pos_z=float(row.get(f"{seg}.position.z", 0)),
                        rot_w=float(row.get(f"{seg}.rotation.w", 0)),
                        rot_x=float(row.get(f"{seg}.rotation.x", 0)),
                        rot_y=float(row.get(f"{seg}.rotation.y", 0)),
                        rot_z=float(row.get(f"{seg}.rotation.z", 0))
                    )
                )

            # Ángulos articulares
            for joint in articulaciones:
                angle = row.get(f"{joint}.angle", None)
                angular_v = row.get(f"{joint}.angular_v", None)
                angular_acc = row.get(f"{joint}.angular_acc", None)

                if pd.notna(angle) or pd.notna(angular_v) or pd.notna(angular_acc):
                    angulos_bulk.append(
                        AnguloArticular(
                            frame_id=frame_id,
                            joint_name=joint,
                            angle=float(angle) if pd.notna(angle) else 0.0,
                            angular_v=float(angular_v) if pd.notna(angular_v) else 0.0,
                            angular_acc=float(angular_acc) if pd.notna(angular_acc) else 0.0
                        )
                    )

            # Contactos
            if contactos:
                contactos_bulk.append(
                    Contacto(
                        frame_id=frame_id,
                        left_foot_contact=bool(row.get("left_foot.contact", 0)),
                        right_foot_contact=bool(row.get("right_foot.contact", 0))
                    )
                )

        # Inserciones masivas
        if cinematica_bulk:
            db.bulk_save_objects(cinematica_bulk)
        if angulos_bulk:
            db.bulk_save_objects(angulos_bulk)
        if contactos_bulk:
            db.bulk_save_objects(contactos_bulk)

        db.commit()

        return {
            "message": "CSV procesado y guardado correctamente (optimizado)",
            "archivo_id": nuevo_archivo.archivo_id,
            "sesion_id": nueva_sesion.sesion_id,
            "frames_insertados": len(frames_bulk),
            "segmentos": len(segmentos),
            "articulaciones": len(articulaciones),
        }

    except Exception as e:
        db.rollback()
        print("Error al procesar CSV:", e)
        raise HTTPException(status_code=500, detail=f"Error al procesar CSV: {str(e)}")


async def procesar_c3d(file: UploadFile, db: Session, current_user: Usuario, sesion_id: int):
    filename = file.filename.lower()
    if not filename.endswith(".c3d"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Solo se permiten archivos con extensión .c3d"
        )

    contents = await file.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".c3d") as temp_file:
        temp_file.write(contents)
        temp_file_path = temp_file.name

    try:
        c3d = ezc3d.c3d(temp_file_path)
    except Exception as e:
        os.unlink(temp_file_path)
        raise HTTPException(status_code=400, detail=f"Error al leer el archivo C3D: {e}")
    finally:
        os.unlink(temp_file_path)

    nueva_sesion = db.query(SesionCaptura).filter(SesionCaptura.sesion_id == sesion_id).first()
    if not nueva_sesion:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")

    archivo = db.query(ArchivoMocap).filter(ArchivoMocap.sesion_id == sesion_id).first()
    if not archivo:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")

    CHUNK = 1000
    frames_batch: List[Dict[str, Any]] = []
    cinem_batch: List[Dict[str, Any]] = []
    
    puntos_labels = c3d['parameters']['POINT']['LABELS']['value']
    puntos_datos = c3d['data']['points']
    num_frames = puntos_datos.shape[2]
    
    segmento_map: Dict[str, int] = {}
    default_segmento_name = "_unknown"
    default_segmento_id = ensure_segmento(db, default_segmento_name, segmento_map)

    for frame_number in range(num_frames):
        frames_batch.append({
            "sesion_id": nueva_sesion.sesion_id,
            "frame_number": frame_number,
            "timestamp_ms": int(frame_number / c3d['parameters']['POINT']['RATE']['value'][0] * 1000)
        })

        for i, label in enumerate(puntos_labels):
            pos_x, pos_y, pos_z = puntos_datos[0, i, frame_number], puntos_datos[1, i, frame_number], puntos_datos[2, i, frame_number]
            if not (pos_x == 0 and pos_y == 0 and pos_z == 0):
                cinem_batch.append({
                    "frame_number": frame_number,
                    "segment_name": label,
                    "pos_x": float(pos_x),
                    "pos_y": float(pos_y),
                    "pos_z": float(pos_z)
                })

        if len(frames_batch) >= CHUNK:
            await flush_batch(db, frames_batch, cinem_batch, [], [], nueva_sesion,
                              file.filename, segmento_map, default_segmento_id)
            frames_batch, cinem_batch = [], []

    if frames_batch:
        await flush_batch(db, frames_batch, cinem_batch, [], [], nueva_sesion,
                          file.filename, segmento_map, default_segmento_id)

    return JSONResponse({"status": "ok", "sesion_id": nueva_sesion.sesion_id})
def is_admin(current_user: Usuario = Depends(get_current_user)):
    if current_user.rol.nombre != "admin" and current_user.rol.nombre != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tiene los permisos de administrador"
        )
    return current_user

def is_super_admin(current_user: Usuario = Depends(get_current_user)):
    if current_user.rol.nombre != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tiene los permisos de super administrador"
        )
    return current_user

class CreateAdmin(BaseModel):
    nombre: str
    email: str
    password: str

@app.post("/create_admin")
def create_admin(admin: CreateAdmin, current_user: Usuario = Depends(get_current_user), db: Session = Depends(get_db)):
    
    if current_user.rol.nombre != "super_admin":
        raise HTTPException(status_code=403, detail="No autorizado")

    nuevo_admin = Usuario(
        nombre=admin.nombre,
        email=admin.email,
        password_hash=hash_password(admin.password),
        rol_id=2  
    )
    db.add(nuevo_admin)
    db.commit()
    db.refresh(nuevo_admin)

    return {"message": "Administrador creado correctamente", "admin_id": nuevo_admin.usuario_id}


class UsuarioCreate(BaseModel):
    
    nombre: str
    email: str
    password: str

# CONTADOR GLOBAL 
@app.post("/register", response_model=UsuarioResponse)
def register_user(user: UsuarioCreate, db: Session = Depends(get_db)):
    # Verificar si el correo ya existe
    existing_user = db.query(Usuario).filter(Usuario.email == user.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El correo ya está registrado"
        )

   
    hashed_password = pwd_context.hash(user.password)
    new_user = Usuario(
        nombre=user.nombre,
        email=user.email,
        password_hash=hashed_password,
        rol_id=1
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@app.post("/login", response_model=Token)
def login_for_access_token(user: UserLogin, db: Session = Depends(get_db)):
    print("DEBUG: login endpoint - db.bind:", db.bind.url) # <-- Confirmar que es SQLite
    user_db = db.query(Usuario).filter(Usuario.email == user.email).first()
    if not user_db or not verify_password(user.password, user_db.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Registrar inicio de sesión
    session_log = log_sesion_user(usuario_id=user_db.usuario_id)
    db.add(session_log)
    db.commit() # <-- Guarda el objeto en la DB
    db.refresh(session_log) # <-- Recarga el objeto para obtener 'id' y 'login_time' generados por la DB
    print(f"DEBUG: login endpoint - ID generado por commit y refresh: {session_log.id}, Login time: {session_log.login_time}")

    # Incrementar contador de usuarios que han entrado
    counter = db.query(UserLoginCounter).first()
    if not counter:
        counter = UserLoginCounter(count=1)
        db.add(counter)
    else:
        counter.count += 1
    db.commit() # <-- Este commit está bien

    access_token = secrets.token_hex(32)
    db_token = Tokens(access_token=access_token, usuario_id=user_db.usuario_id)
    db.add(db_token)
    db.commit()
    db.refresh(db_token) # <-- Este refresh es para 'db_token'

    return {"access_token": access_token}

@app.post("/login", response_model=Token)
def login_for_access_token(user: UserLogin, db: Session = Depends(get_db)):
    print("DEBUG: login endpoint - db.bind:", db.bind.url) # <-- Confirmar que es SQLite
    user_db = db.query(Usuario).filter(Usuario.email == user.email).first()
    if not user_db or not verify_password(user.password, user_db.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Registrar inicio de sesión
    session_log = log_sesion_user(usuario_id=user_db.usuario_id)
    db.add(session_log)
    db.commit() # <-- Guarda el objeto en la DB
    db.refresh(session_log) # <-- Recarga el objeto para obtener 'id' y 'login_time' generados por la DB
    print(f"DEBUG: login endpoint - ID generado por commit y refresh: {session_log.id}, Login time: {session_log.login_time}")

    # Incrementar contador de usuarios que han entrado
    counter = db.query(UserLoginCounter).first()
    if not counter:
        counter = UserLoginCounter(count=1)
        db.add(counter)
    else:
        counter.count += 1
    db.commit() # <-- Este commit está bien

    access_token = secrets.token_hex(32)
    db_token = Tokens(access_token=access_token, usuario_id=user_db.usuario_id)
    db.add(db_token)
    db.commit()
    db.refresh(db_token) # <-- Este refresh es para 'db_token'

    return {"access_token": access_token}

@app.get("/admin/session-logs/")
def get_session_logs(current_user: Usuario = Depends(is_admin), db: Session = Depends(get_db)):
    logs = db.query(log_sesion_user).all()
    return [
        {
            "id": log.id,
            "usuario_id": log.usuario_id,
            "login_time": log.login_time,
            "logout_time": log.logout_time
        }
        for log in logs
    ]

@app.get("/admin/users/{user_id}")
def get_user_by_id(user_id: int, db: Session = Depends(get_db), current_user: Usuario = Depends(is_admin)):
    user = db.query(Usuario).filter(Usuario.usuario_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return {"usuario_id": user.usuario_id, "nombre": user.nombre}

@app.get("/admin/user-count/", response_model=dict)
def get_user_login_count(current_user: Usuario = Depends(is_admin), db: Session = Depends(get_db)):
    counter = db.query(UserLoginCounter).first()
    if not counter:
        return {"total_users": 0}
    return {"total_users": counter.count}

@app.get("/users/me")
def read_users_me(current_user: Usuario = Depends(get_current_user), db: Session = Depends(get_db)):
    return {
        "usuario_id": current_user.usuario_id,
        "nombre": current_user.nombre,
        "email": current_user.email,
        "rol": {
            "rol_id": current_user.rol.rol_id,
            "nombre": current_user.rol.nombre
        }
    }
    
def normalize_seg_name(name: str) -> str:
    if not name:
        return ""
    return str(name).split('.', 1)[0].strip().lower()

def ensure_segmento(db: Session, name: str, segmento_map: Dict[str, int]):
    base = normalize_seg_name(name)
    if not base:
        return None

    if base in segmento_map:
        return segmento_map[base]

    s = db.query(Segmento).filter_by(nombre=base).first()
    if not s:
        s = Segmento(nombre=base)
        db.add(s)
        db.commit()
        db.refresh(s)
        print(f"Nuevo segmento creado: {s.nombre} (ID: {s.segmento_id})")
    
    segmento_map[base] = s.segmento_id
    return s.segmento_id

    
async def flush_batch(db: Session, frames_batch, cinem_batch, angulo_batch, contacto_batch, nueva_sesion, file_name, segmento_map, default_segmento_id):
    if not frames_batch:
        return

    db.bulk_insert_mappings(Frame, frames_batch)
    db.commit()

    nums = list({m["frame_number"] for m in frames_batch})
    frames_db = db.query(Frame).filter(
        Frame.sesion_id == nueva_sesion.sesion_id,
        Frame.frame_number.in_(nums)
    ).all()
    frame_map = {f.frame_number: f.frame_id for f in frames_db}

    if cinem_batch:
        cinem_to_insert = []
        for m in cinem_batch:
            fid = frame_map.get(m["frame_number"])
            if not fid:
                continue
            seg_id = ensure_segmento(db, m.get("segment_name"), segmento_map) if m.get("segment_name") else default_segmento_id
            cinem_to_insert.append({
                "frame_id": fid,
                "segmento_id": seg_id,
                "pos_x": m.get("pos_x"),
                "pos_y": m.get("pos_y"),
                "pos_z": m.get("pos_z"),
                "rot_w": m.get("rot_w", 0),
                "rot_x": m.get("rot_x", 0),
                "rot_y": m.get("rot_y", 0),
                "rot_z": m.get("rot_z", 0),
                "nombre_archivo": file_name
            })
        if cinem_to_insert:
            db.bulk_insert_mappings(Cinematica, cinem_to_insert)
            db.commit()

    if angulo_batch:
        ang_to_insert = []
        for m in angulo_batch:
            fid = frame_map.get(m["frame_number"])
            if not fid:
                continue
            ang_to_insert.append({
                "frame_id": fid,
                "joint_name": m.get("joint_name"),
                "angle": m.get("angle"),
                "angular_v": m.get("angular_v"),
                "angular_acc": m.get("angular_acc")
            })
        if ang_to_insert:
            db.bulk_insert_mappings(AnguloArticular, ang_to_insert)
            db.commit()

    if contacto_batch:
        cont_to_insert = []
        for m in contacto_batch:
            fid = frame_map.get(m["frame_number"])
            if not fid:
                continue
            cont_to_insert.append({
                "frame_id": fid,
                "left_foot_contact": m.get("left_foot_contact"),
                "right_foot_contact": m.get("right_foot_contact")
            })
        if cont_to_insert:
            db.bulk_insert_mappings(Contacto, cont_to_insert)
            db.commit()

# ---
# ENDPOINTS
# ---

@app.get("/data/3d")
def get_3d_data(nombre_archivo: str, db: Session = Depends(get_db), current_user: Usuario = Depends(get_current_user)):
    archivo = db.query(ArchivoMocap).filter(ArchivoMocap.nombre_archivo == nombre_archivo).first()
    if not archivo:
        raise HTTPException(status_code=404, detail=f"Archivo '{nombre_archivo}' no encontrado")

    frame_ids_query = db.query(Frame.frame_id).filter(Frame.sesion_id == archivo.sesion_id).limit(50).scalar_subquery()

    data = (
        db.query(Cinematica, Segmento.nombre, Cinematica.frame_id)
        .join(Segmento, Cinematica.segmento_id == Segmento.segmento_id)
        .filter(Cinematica.frame_id.in_(frame_ids_query))
        .order_by(Cinematica.frame_id, Segmento.nombre)
        .all()
    )

    frames = defaultdict(list)
    
    for c, nombre_segmento, frame_id in data:
        
        if nombre_archivo.endswith(".csv") and nombre_segmento == "1":
            continue  
        
        frames[frame_id].append({
            "segmento": nombre_segmento,
            "x": c.pos_x,
            "y": c.pos_y,
            "z": c.pos_z,
            "rot_w": c.rot_w,
            "rot_x": c.rot_x,
            "rot_y": c.rot_y,
            "rot_z": c.rot_z,
        })

    frames_ordenados = [frames[k] for k in sorted(frames.keys())]
    print("Frames finales cargados:", len(frames_ordenados))
    
    
    
    file_type = "c3d" if nombre_archivo.endswith(".c3d") else "csv"
    
    return {
        "frames": frames_ordenados,
        "file_type": file_type
    }
    

@app.delete("/archivo/{nombre_archivo}")
def eliminar_archivo(nombre_archivo: str, db: Session = Depends(get_db), current_user: Usuario = Depends(is_admin)):
    # Buscar el archivo
    archivo = db.query(ArchivoMocap).filter(ArchivoMocap.nombre_archivo == nombre_archivo).first()
    if not archivo:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")

    sesion_id = archivo.sesion_id
    CHUNK_SIZE = 1000 

    try:
       

        # 1. Eliminar Contactos en bloques
        while True:
            subquery = db.query(Contacto.contacto_id).join(Frame).filter(Frame.sesion_id == sesion_id).limit(CHUNK_SIZE).subquery()
            result = db.query(Contacto).filter(Contacto.contacto_id.in_(subquery)).delete(synchronize_session=False)
            db.commit()
            if result == 0:
                break

        # 2. Eliminar Ángulos Articulares en bloques
        while True:
            subquery = db.query(AnguloArticular.angulo_id).join(Frame).filter(Frame.sesion_id == sesion_id).limit(CHUNK_SIZE).subquery()
            result = db.query(AnguloArticular).filter(AnguloArticular.angulo_id.in_(subquery)).delete(synchronize_session=False)
            db.commit()
            if result == 0:
                break

        # 3. Eliminar Cinemática en bloques
        while True:
            subquery = db.query(Cinematica.cinematica_id).join(Frame).filter(Frame.sesion_id == sesion_id).limit(CHUNK_SIZE).subquery()
            result = db.query(Cinematica).filter(Cinematica.cinematica_id.in_(subquery)).delete(synchronize_session=False)
            db.commit()
            if result == 0:
                break

        # 4. Eliminar Frames en bloques
        while True:
            subquery = db.query(Frame.frame_id).filter(Frame.sesion_id == sesion_id).limit(CHUNK_SIZE).subquery()
            result = db.query(Frame).filter(Frame.frame_id.in_(subquery)).delete(synchronize_session=False)
            db.commit()
            if result == 0:
                break

        # 5. ELIMINAR EL REGISTRO DE LA BASE DE DATOS SIEMPRE
 
        db.delete(archivo)
        db.commit()  

        # 6. ELIMINAR LA SESIÓN DE CAPTURA SIEMPRE
      
        db.query(SesionCaptura).filter(SesionCaptura.sesion_id == sesion_id).delete(synchronize_session=False)
        db.commit()

        return {"message": f"Archivo '{nombre_archivo}' y todos sus datos relacionados han sido eliminados correctamente"}

    except Exception as e:
        db.rollback()
        print(f"Error detallado al eliminar '{nombre_archivo}': {e}") # Log del error
        raise HTTPException(status_code=500, detail=f"Error al eliminar archivo: {str(e)}")

@app.delete("/admin/users/{user_id}")
def delete_user(
    user_id: int, 
    current_user: Usuario = Depends(is_super_admin), 
    db: Session = Depends(get_db)
):
  
    usuario_a_eliminar = db.query(Usuario).filter(Usuario.usuario_id == user_id).first()
    if not usuario_a_eliminar:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

 
    if usuario_a_eliminar.usuario_id == current_user.usuario_id:
         raise HTTPException(status_code=400, detail="No puedes eliminarte a ti mismo")

    # Eliminar datos relacionados
 
    db.query(Tokens).filter(Tokens.usuario_id == user_id).delete(synchronize_session=False)

    # 2. Eliminar registros de sesión del usuario (log_sesion_user)
    db.query(log_sesion_user).filter(log_sesion_user.usuario_id == user_id).delete(synchronize_session=False)

    # 3. Eliminar el usuario
    db.delete(usuario_a_eliminar)
    db.commit()

    return {"message": f"Usuario '{usuario_a_eliminar.nombre}' eliminado correctamente"}



class PasswordUpdateRequest(BaseModel):
    new_password: str

@app.put("/admin/users/{user_id}/password")
def update_user_password(
    user_id: int,
    password_update: PasswordUpdateRequest, 
    current_user: Usuario = Depends(is_super_admin),
    db: Session = Depends(get_db)
):
    usuario_a_actualizar = db.query(Usuario).filter(Usuario.usuario_id == user_id).first()
    if not usuario_a_actualizar:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    hashed_password = hash_password(password_update.new_password) 
    usuario_a_actualizar.password_hash = hashed_password

    db.commit()

    return {"message": f"Contraseña del usuario '{usuario_a_actualizar.nombre}' actualizada correctamente"}

@app.put("/archivo/{nombre_archivo}")
async def actualizar_archivo(nombre_archivo: str, file: UploadFile = File(...), db: Session = Depends(get_db), current_user: Usuario = Depends(is_admin)):
    # Verificar si el archivo existe
    archivo_existente = db.query(ArchivoMocap).filter(ArchivoMocap.nombre_archivo == nombre_archivo).first()
    if not archivo_existente:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")

    # Verificar que el tipo del nuevo archivo coincida con el existente
    extension_existente = nombre_archivo.lower().split('.')[-1]
    extension_nueva = file.filename.lower().split('.')[-1]

    if extension_existente != extension_nueva:
        raise HTTPException(status_code=400, detail=f"Tipo de archivo incorrecto. Se esperaba .{extension_existente}, se recibió .{extension_nueva}")

    sesion_id = archivo_existente.sesion_id

    try:
      
        # 1. Eliminar Contactos relacionados con la sesión
        db.query(Contacto).filter(
            Contacto.frame_id.in_(
                db.query(Frame.frame_id).filter(Frame.sesion_id == sesion_id)
            )
        ).delete(synchronize_session=False)

        # 2. Eliminar Ángulos Articulares relacionados con la sesión
        db.query(AnguloArticular).filter(
            AnguloArticular.frame_id.in_(
                db.query(Frame.frame_id).filter(Frame.sesion_id == sesion_id)
            )
        ).delete(synchronize_session=False)

        # 3. Eliminar Cinemática relacionada con la sesión
        db.query(Cinematica).filter(
            Cinematica.frame_id.in_(
                db.query(Frame.frame_id).filter(Frame.sesion_id == sesion_id)
            )
        ).delete(synchronize_session=False)

        # 4. Eliminar Frames relacionados con la sesión
        db.query(Frame).filter(Frame.sesion_id == sesion_id).delete(synchronize_session=False)

        db.commit() 

        # GUARDAR Y ACTUALIZAR EL NUEVO ARCHIVO
        ruta_nueva = f"uploads/{file.filename}"  
        os.makedirs(os.path.dirname(ruta_nueva), exist_ok=True)

        # Guardar nuevo archivo
        with open(ruta_nueva, "wb") as f:
            f.write(await file.read())

        # Actualizar registro en la base de datos
        archivo_existente.nombre_archivo = file.filename
        archivo_existente.ruta_archivo = ruta_nueva
        archivo_existente.fecha_subida = datetime.utcnow()
        db.commit()


        return {"message": f"Archivo '{nombre_archivo}' actualizado correctamente. Los datos antiguos han sido eliminados."}

    except Exception as e:
        db.rollback()
        print(f"Error detallado al actualizar '{nombre_archivo}': {e}") # Log del error
        raise HTTPException(status_code=500, detail=f"Error al actualizar archivo: {str(e)}")

@app.get("/lista_archivos/")
def lista_archivos(db: Session = Depends(get_db),current_user: Usuario = Depends(get_current_user)):
    archivos = db.query(ArchivoMocap.nombre_archivo).distinct().all()
    return [a[0] for a in archivos if a[0] is not None]

@app.get("/admin/users/", response_model=List[UsuarioResponse])
def get_all_users(current_user: Usuario = Depends(is_super_admin), db: Session = Depends(get_db)):
   
    # Usar joinedload para cargar la relación 'rol' en la misma consulta
    usuarios = db.query(Usuario).options(joinedload(Usuario.rol)).all()
    return usuarios

@app.get("/download/{filename}")
def download_file(
    filename: str,
    db: Session = Depends(get_db),
    current_user: Usuario = Depends(get_current_user)
):
    archivo = db.query(ArchivoMocap).filter(ArchivoMocap.nombre_archivo == filename).first()
    if not archivo:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")

    # Usar la ruta almacenada en la base de datos
    file_path = archivo.ruta_archivo

    # Verificar que el archivo exista físicamente
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Archivo no encontrado en el sistema: {file_path}")

    # Servir el archivo
    return FileResponse(
        path=file_path,
        filename=filename,
        media_type='application/octet-stream'
    )
    
UPLOAD_FOLDER = "downloads" # Ruta relativa desde la raíz del proyecto
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# ---
# ENDPOINT PARA ARCHIVOS CSV 
# ---

@app.post("/upload_csv/")
async def upload_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    

    try:
        #  Leer CSV completo 
        contents = await file.read()
        df = pd.read_csv(io.StringIO(contents.decode("utf-8")))

        if df.empty:
            raise HTTPException(status_code=400, detail="El archivo CSV está vacío")

        df = df.dropna(how="all").fillna(0)

        # Crear nueva sesión de captura
        nueva_sesion = SesionCaptura(
            usuario_id=current_user.usuario_id,
            fecha=datetime.now(timezone.utc),
            descripcion=f"Sesión automática generada al subir {file.filename}"
        )
        db.add(nueva_sesion)
        db.commit()
        db.refresh(nueva_sesion)

        # Crear registro de archivo
        nuevo_archivo = ArchivoMocap(
            sesion_id=nueva_sesion.sesion_id,
            nombre_archivo=file.filename,
            ruta_archivo=f"/downloads/{file.filename}",
            fecha_subida=datetime.now(timezone.utc)
        )
        db.add(nuevo_archivo)
        db.commit()
        db.refresh(nuevo_archivo)

        #  Detectar columnas
        columnas = df.columns
        segmentos = sorted(set(col.split('.')[0] for col in columnas if ".position" in col or ".rotation" in col))
        articulaciones = sorted(set(col.split('.')[0] for col in columnas if ".angle" in col))
        contactos = [col for col in columnas if ".contact" in col]

        # Crear segmentos si no existen
        segmentos_db = {}
        for seg in segmentos:
            existente = db.query(Segmento).filter_by(nombre=seg).first()
            if not existente:
                nuevo_seg = Segmento(nombre=seg)
                db.add(nuevo_seg)
                db.commit()
                db.refresh(nuevo_seg)
                segmentos_db[seg] = nuevo_seg
            else:
                segmentos_db[seg] = existente

        #  Acumuladores para inserción masiva
        frames_bulk = []
        cinematica_bulk = []
        angulos_bulk = []
        contactos_bulk = []

        # Recorrer frames
        for _, row in df.iterrows():
            frame = Frame(
                sesion_id=nueva_sesion.sesion_id,
                frame_number=int(row.get("frame_number", 0)),
                timestamp_ms=int(row.get("frame_timestamp", 0))
            )
            frames_bulk.append(frame)

        # Guardar todos los frames primero
        db.bulk_save_objects(frames_bulk)
        db.commit()

        # Obtener los IDs asignados a los frames
        frames_guardados = (
            db.query(Frame)
            .filter(Frame.sesion_id == nueva_sesion.sesion_id)
            .order_by(Frame.frame_id)
            .all()
        )

        #  Generar registros secundarios (cinemática, ángulos, contactos)
        for idx, (_, row) in enumerate(df.iterrows()):
            frame_id = frames_guardados[idx].frame_id

            # Cinemática
            for seg in segmentos:
                cinematica_bulk.append(
                Cinematica(
                frame_id=frame_id,
                segmento_id=segmentos_db[seg].segmento_id,
                pos_x=float(row.get(f"{seg}.position.x", 0)),
                pos_y=float(row.get(f"{seg}.position.y", 0)),
                pos_z=float(row.get(f"{seg}.position.z", 0)),
                rot_w=float(row.get(f"{seg}.rotation.w", 0)),
                rot_x=float(row.get(f"{seg}.rotation.x", 0)),
                rot_y=float(row.get(f"{seg}.rotation.y", 0)),
                rot_z=float(row.get(f"{seg}.rotation.z", 0))
                )
            )


            # Ángulos articulares
            for joint in articulaciones:
                angle = getattr(row, f"{joint}.angle", None)
                angular_v = getattr(row, f"{joint}.angular_v", None)
                angular_acc = getattr(row, f"{joint}.angular_acc", None)

                if pd.notna(angle) or pd.notna(angular_v) or pd.notna(angular_acc):
                    angulos_bulk.append(
                        AnguloArticular(
                            frame_id=frame_id,
                            joint_name=joint,
                            angle=float(angle) if pd.notna(angle) else 0.0,
                            angular_v=float(angular_v) if pd.notna(angular_v) else 0.0,
                            angular_acc=float(angular_acc) if pd.notna(angular_acc) else 0.0
                        )
                    )

            # Contactos
            if contactos:
                contactos_bulk.append(
                    Contacto(
                        frame_id=frame_id,
                        left_foot_contact=bool(getattr(row, "left_foot.contact", 0)),
                        right_foot_contact=bool(getattr(row, "right_foot.contact", 0))
                    )
                )

        # Inserciones masivas
        if cinematica_bulk:
            db.bulk_save_objects(cinematica_bulk)
        if angulos_bulk:
            db.bulk_save_objects(angulos_bulk)
        if contactos_bulk:
            db.bulk_save_objects(contactos_bulk)

        db.commit()
        file_location = os.path.join(UPLOAD_FOLDER, file.filename)
        with open(file_location, "wb") as f:
            f.write(contents)
            
        return {
            "message": " CSV procesado y guardado correctamente (optimizado)",
            "archivo_id": nuevo_archivo.archivo_id,
            "sesion_id": nueva_sesion.sesion_id,
            "frames_insertados": len(frames_bulk),
            "segmentos": len(segmentos),
            "articulaciones": len(articulaciones),
        }

    except Exception as e:
        db.rollback()
        print(" Error al procesar CSV:", e)
        raise HTTPException(status_code=500, detail=f"Error al procesar CSV: {str(e)}")


# ============================================================
#  ENDPOINT: Subir archivo C3D
# ============================================================
@app.post("/upload_c3d/")
async def upload_c3d(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: Usuario = Depends(is_admin)
):
    filename = file.filename.lower()
    if not filename.endswith(".c3d"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Solo se permiten archivos con extensión .c3d"
        )

    existing = db.query(ArchivoMocap).filter(ArchivoMocap.nombre_archivo == file.filename).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"El archivo '{file.filename}' ya fue subido anteriormente."
        )

    contents = await file.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".c3d") as temp_file:
        temp_file.write(contents)
        temp_file_path = temp_file.name

    try:
        c3d = ezc3d.c3d(temp_file_path)
    except Exception as e:
        os.unlink(temp_file_path)
        raise HTTPException(status_code=400, detail=f"Error al leer el archivo C3D: {e}")
    finally:
        os.unlink(temp_file_path)

    nueva_sesion = SesionCaptura(usuario_id=current_user.usuario_id, descripcion=f"Import {file.filename}")
    db.add(nueva_sesion); db.commit(); db.refresh(nueva_sesion)

    archivo = ArchivoMocap(sesion_id=nueva_sesion.sesion_id, nombre_archivo=file.filename, ruta_archivo=file.filename)
    db.add(archivo); db.commit(); db.refresh(archivo)

    CHUNK = 1000
    frames_batch: List[Dict[str, Any]] = []
    cinem_batch: List[Dict[str, Any]] = []
    
    puntos_labels = c3d['parameters']['POINT']['LABELS']['value']
    puntos_datos = c3d['data']['points']
    num_frames = puntos_datos.shape[2]
    
    segmento_map: Dict[str, int] = {}
    default_segmento_name = "_unknown"
    default_segmento_id = ensure_segmento(db, default_segmento_name, segmento_map)

    for frame_number in range(num_frames):
        frames_batch.append({
            "sesion_id": nueva_sesion.sesion_id,
            "frame_number": frame_number,
            "timestamp_ms": int(frame_number / c3d['parameters']['POINT']['RATE']['value'][0] * 1000)
        })

        for i, label in enumerate(puntos_labels):
            pos_x, pos_y, pos_z = puntos_datos[0, i, frame_number], puntos_datos[1, i, frame_number], puntos_datos[2, i, frame_number]
            if not (pos_x == 0 and pos_y == 0 and pos_z == 0):
                cinem_batch.append({
                    "frame_number": frame_number,
                    "segment_name": label,
                    "pos_x": float(pos_x),
                    "pos_y": float(pos_y),
                    "pos_z": float(pos_z)
                })

        if len(frames_batch) >= CHUNK:
            await flush_batch(db, frames_batch, cinem_batch, [], [], nueva_sesion,
                              file.filename, segmento_map, default_segmento_id)
            frames_batch, cinem_batch = [], []

    if frames_batch:
        await flush_batch(db, frames_batch, cinem_batch, [], [], nueva_sesion,
                          file.filename, segmento_map, default_segmento_id)

    return JSONResponse({"status": "ok", "sesion_id": nueva_sesion.sesion_id})