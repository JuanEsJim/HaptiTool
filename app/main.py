import io, time, csv, ezc3d
from io import BytesIO
from typing import List, Dict, Any
from collections import defaultdict
import traceback
import tempfile
import os
import json
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status, APIRouter
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, Column, Integer, DateTime, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext
import secrets
from datetime import datetime
from database import SessionLocal, engine, Base
from models import AnguloArticular, ArchivoMocap, Cinematica, Contacto, Frame, Segmento, SesionCaptura, Usuario, Rol, Tokens, log_sesion_user
from schemas import UsuarioCreate, UsuarioResponse, UserLogin, Token, ArchivoDetalle
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

app = FastAPI()

# Inicialización del contexto de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Asegurar que las tablas existen en la BD
Base.metadata.create_all(bind=engine)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependencia de la base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


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

class UserLoginCounter(Base):
    __tablename__ = "user_login_counter"
    id = Column(Integer, primary_key=True, default=1)
    count = Column(Integer, default=0)



@app.post("/login", response_model=Token)
def login_for_access_token(user: UserLogin, db: Session = Depends(get_db)):
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
    db.commit()
    db.refresh(session_log)

    # Incrementar contador de usuarios que han entrado
    counter = db.query(UserLoginCounter).first()
    if not counter:
        counter = UserLoginCounter(count=1)
        db.add(counter)
    else:
        counter.count += 1
    db.commit()

    access_token = secrets.token_hex(32)
    db_token = Tokens(access_token=access_token, usuario_id=user_db.usuario_id)
    db.add(db_token)
    db.commit()
    db.refresh(db_token)

    return {"access_token": access_token}

@app.post("/logout")
def logout_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Buscar el token
    db_token = db.query(Tokens).filter(Tokens.access_token == token).first()
    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
        )

    # Buscar la sesión más reciente sin logout_time
    session = db.query(log_sesion_user).filter(
        log_sesion_user.usuario_id == db_token.usuario_id,
        log_sesion_user.logout_time == None
    ).order_by(log_sesion_user.login_time.desc()).first()

    if session:
        session.logout_time = datetime.utcnow()
        db.commit()

    # Eliminar el token
    db.delete(db_token)
    db.commit()

    return {"message": "Sesión cerrada correctamente"}

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
def read_users_me(current_user: Usuario = Depends(get_current_user)):
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
        db.add(s); db.commit(); db.refresh(s)
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

    frame_ids = db.query(Frame.frame_id).filter(Frame.sesion_id == archivo.sesion_id).limit(50).subquery()

    data = (
        db.query(Cinematica, Segmento.nombre, Cinematica.frame_id)
        .join(Segmento, Cinematica.segmento_id == Segmento.segmento_id)
        .filter(Cinematica.frame_id.in_(frame_ids))
        .order_by(Cinematica.frame_id, Segmento.nombre)
        .all()
    )

    frames = defaultdict(list)
    
    for c, nombre_segmento, frame_id in data:
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
    return frames_ordenados

@app.get("/data/2d")
def get_2d_data(nombre_archivo: str, db: Session = Depends(get_db),current_user: Usuario = Depends(get_current_user)):
    data = (
        db.query(Cinematica)
        .join(Frame, Cinematica.frame_id == Frame.frame_id)
        .join(SesionCaptura, Frame.sesion_id == SesionCaptura.sesion_id)
        .join(ArchivoMocap, SesionCaptura.sesion_id == ArchivoMocap.sesion_id)
        .filter(ArchivoMocap.nombre_archivo == nombre_archivo)
        .limit(500)
        .all()
    )
    return [{"x": d.pos_x, "y": d.pos_y} for d in data]

@app.get("/lista_archivos/")
def lista_archivos(db: Session = Depends(get_db),current_user: Usuario = Depends(get_current_user)):
    archivos = db.query(ArchivoMocap.nombre_archivo).distinct().all()
    return [a[0] for a in archivos if a[0] is not None]

# ---
# ENDPOINT PARA ARCHIVOS CSV 
# ---
@app.post("/upload_csv/")
async def upload_csv(file: UploadFile = File(...), db: Session = Depends(get_db), current_user: Usuario = Depends(is_admin)):
    contents = await file.read()
    text = contents.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))

    nueva_sesion = SesionCaptura(usuario_id=current_user.usuario_id, descripcion=f"Import {file.filename}")
    db.add(nueva_sesion); db.commit(); db.refresh(nueva_sesion)

    archivo = ArchivoMocap(sesion_id=nueva_sesion.sesion_id, nombre_archivo=file.filename, ruta_archivo=file.filename)
    db.add(archivo); db.commit(); db.refresh(archivo)

    CHUNK = 1000
    frames_batch: List[Dict[str, Any]] = []
    cinem_batch: List[Dict[str, Any]] = []
    angulo_batch: List[Dict[str, Any]] = []
    contacto_batch: List[Dict[str, Any]] = []

    segmento_map: Dict[str, int] = {}
    frame_map: Dict[int, int] = {}  

    default_segmento_name = "_unknown"
    
    default_segmento_id = ensure_segmento(db, default_segmento_name, segmento_map) 
    
    if default_segmento_id is None:
        s_def = Segmento(nombre=default_segmento_name)
        db.add(s_def); db.commit(); db.refresh(s_def)
        default_segmento_id = s_def.segmento_id
        segmento_map[default_segmento_name] = default_segmento_id

    column_mappings: Dict[str, Dict[str, Any]] = {}
    for col in reader.fieldnames or []:
        col_str = str(col).strip()
        parts = col_str.split('.')
        
        def seg_of(p): return p.strip().lower()
        
        if len(parts) >= 3:
            segment = seg_of(parts[0])
            prop = seg_of(parts[1])
            axis = seg_of(parts[-1])
        
        elif len(parts) == 2:
            segment = seg_of(parts[0])
            prop = seg_of(parts[1])
            axis = None
        else:
            segment = None
            prop = None
            axis = None
        
        if prop in ("position", "pos", "translation"):
            if axis == "x": target = "pos_x"
            elif axis == "y": target = "pos_y"
            elif axis == "z": target = "pos_z"
            else: target = None
            if target:
                column_mappings[col_str] = {"type": "cinematica", "segment": segment, "target": target}
                continue
        if prop in ("rotation", "rot", "orientation"):
            if axis == "w": target = "rot_w"
            elif axis == "x": target = "rot_x"
            elif axis == "y": target = "rot_y"
            elif axis == "z": target = "rot_z"
            else: target = None
            if target:
                column_mappings[col_str] = {"type": "cinematica", "segment": segment, "target": target}
                continue
        
        if prop in ("contact", "contact_state", "contactstatus"):
            side = axis or ""  
            column_mappings[col_str] = {"type": "contact", "segment": segment, "side": side}
            continue
            
        if prop in ("angular", "angle", "joint", "joint_angle") or (prop and prop.startswith("angular")):
            subaxis = None
            if prop and prop.startswith("angular_"):
                subaxis = prop.split("_", 1)[1]
            
            if axis in ("v", "vel", "velocity") or subaxis in ("v", "vel", "velocity"):
                tgt = "angular_v"
            elif axis in ("acc", "a", "acceleration") or subaxis in ("acc", "a", "acceleration"):
                tgt = "angular_acc"
            else:
                tgt = "angle"
            column_mappings[col_str] = {"type": "angulo", "segment": segment, "target": tgt}
            continue

        simple = col_str.lower()
        if simple in ("pos_x","pos_y","pos_z","rot_w","rot_x","rot_y","rot_z"):
            column_mappings[col_str] = {"type": "cinematica", "segment": None, "target": simple}
        elif simple in ("frame_number", "frame_timestamp", "timestamp_ms", "frame_timestamp_ms"):
            column_mappings[col_str] = {"meta": "frame"}
        elif simple in ("left_foot_contact","right_foot_contact","left_contact","right_contact"):
            side = "left" if "left" in simple else "right"
            column_mappings[col_str] = {"type": "contact", "segment": None, "side": side}
        elif simple in ("angle","angle_deg"):
            column_mappings[col_str] = {"type": "angulo", "segment": None, "target": "angle"}
        elif simple in ("angular_v","angular_velocity","angularvel","angvel"):
            column_mappings[col_str] = {"type": "angulo", "segment": None, "target": "angular_v"}
        elif simple in ("angular_acc","angular_acceleration","angacc","acceleration"):
            column_mappings[col_str] = {"type": "angulo", "segment": None, "target": "angular_acc"}
    
    reader_iter = iter(reader)
    while True:
        try:
            row = next(reader_iter)
        except StopIteration:
            break
        except Exception as e:
            print(f"Error reading row: {e}")
            continue

        try:
            fnum = int(row.get("frame_number") or row.get("frame_number".lower()) or "0")
        except (ValueError, TypeError):
            continue

        frames_batch.append({
            "sesion_id": nueva_sesion.sesion_id,
            "frame_number": fnum,
            "timestamp_ms": int(float(row.get("Time") or "0") * 1000) if row.get("Time") else fnum
        })

        seg_values: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"pos_x": None, "pos_y": None, "pos_z": None, "rot_w": None, "rot_x": None, "rot_y": None, "rot_z": None})
        contact_vals: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"left": None, "right": None}) 
        ang_vals: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"angle": None, "angular_v": None, "angular_acc": None})
        
        for col_name, meta in column_mappings.items():
            raw = row.get(col_name)
            if raw is None or raw == "" or meta.get("meta") == "frame":
                continue
            
            try:
                mtype = meta.get("type")
                if mtype == "cinematica":
                    seg = normalize_seg_name(meta.get("segment") or "") or default_segmento_name
                    target = meta.get("target")
                    if target:
                        seg_values[seg][target] = float(raw)
                elif mtype == "contact":
                    seg = normalize_seg_name(meta.get("segment") or "") or default_segmento_name
                    side = meta.get("side") or ""
                    val = None
                    try: val = bool(int(raw))
                    except (ValueError, TypeError):
                        if str(raw).lower() in ("true","1","yes","y"): val = True
                        elif str(raw).lower() in ("false","0","no","n"): val = False
                    
                    if "left" in side: contact_vals[seg]["left"] = val
                    elif "right" in side: contact_vals[seg]["right"] = val
                    else:
                        if "left" in seg: contact_vals[seg]["left"] = val
                        elif "right" in seg: contact_vals[seg]["right"] = val
                elif mtype == "angulo":
                    seg = normalize_seg_name(meta.get("segment") or "") or default_segmento_name
                    target = meta.get("target")
                    if target:
                        ang_vals[seg][target] = float(raw)
            except (ValueError, TypeError):
                continue

        for seg_name, vals in seg_values.items():
            seg_id = ensure_segmento(db, seg_name, segmento_map) or default_segmento_id
            cinem_batch.append({
                "frame_number": fnum, "segmento_id": seg_id, "pos_x": vals.get("pos_x"), "pos_y": vals.get("pos_y"),
                "pos_z": vals.get("pos_z"), "rot_w": vals.get("rot_w", 0), "rot_x": vals.get("rot_x", 0),
                "rot_y": vals.get("rot_y", 0), "rot_z": vals.get("rot_z", 0),
            })

        for seg_name, vals in ang_vals.items():
            if any(v is not None for v in vals.values()):
                angulo_batch.append({
                    "frame_number": fnum, "joint_name": seg_name, "angle": vals.get("angle"),
                    "angular_v": vals.get("angular_v"), "angular_acc": vals.get("angular_acc")
                })
        
        combined_left, combined_right = None, None
        for seg_name, vals in contact_vals.items():
            if vals.get("left") is not None: combined_left = vals["left"]
            if vals.get("right") is not None: combined_right = vals["right"]
        if combined_left is not None or combined_right is not None:
            contacto_batch.append({
                "frame_number": fnum, "left_foot_contact": combined_left, "right_foot_contact": combined_right
            })

        if len(frames_batch) >= CHUNK:
            await flush_batch(db, frames_batch, cinem_batch, angulo_batch, contacto_batch, nueva_sesion, file.filename, segmento_map, default_segmento_id)
            frames_batch, cinem_batch, angulo_batch, contacto_batch = [], [], [], []
    
    if frames_batch:
        await flush_batch(db, frames_batch, cinem_batch, angulo_batch, contacto_batch, nueva_sesion, file.filename, segmento_map, default_segmento_id)

    return JSONResponse({"status": "ok", "sesion_id": nueva_sesion.sesion_id})

# ---
# ENDPOINT PARA ARCHIVOS C3D
# ---
@app.post("/upload_c3d/")
async def upload_csv(file: UploadFile = File(...), db: Session = Depends(get_db), current_user: Usuario = Depends(is_admin)):
    contents = await file.read()
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".c3d") as temp_file:
        temp_file.write(contents)
        temp_file_path = temp_file.name

    try:
        c3d = ezc3d.c3d(temp_file_path)
    except Exception as e:
        os.unlink(temp_file_path)
        return JSONResponse({"status": "error", "message": f"Error al leer el archivo C3D: {e}"}, status_code=400)
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
            pos_x = puntos_datos[0, i, frame_number]
            pos_y = puntos_datos[1, i, frame_number]
            pos_z = puntos_datos[2, i, frame_number]

            if not (pos_x == 0 and pos_y == 0 and pos_z == 0):
                cinem_batch.append({
                    "frame_number": frame_number,
                    "segment_name": label,
                    "pos_x": float(pos_x),
                    "pos_y": float(pos_y),
                    "pos_z": float(pos_z)
                })

        if len(frames_batch) >= CHUNK:
            await flush_batch(db, frames_batch, cinem_batch, [], [], nueva_sesion, file.filename, segmento_map, default_segmento_id)
            frames_batch = []
            cinem_batch = []
            
    if frames_batch:
        await flush_batch(db, frames_batch, cinem_batch, [], [], nueva_sesion, file.filename, segmento_map, default_segmento_id)

    return JSONResponse({"status": "ok", "sesion_id": nueva_sesion.sesion_id})

@app.get("/data/angles")
def get_angles(nombre_archivo: str, db: Session = Depends(get_db), current_user: Usuario = Depends(get_current_user)):
    rows = db.query(AnguloArticular, Frame.frame_number).\
        join(Frame, AnguloArticular.frame_id == Frame.frame_id).\
        join(ArchivoMocap, ArchivoMocap.sesion_id == Frame.sesion_id).\
        filter(ArchivoMocap.nombre_archivo == nombre_archivo).all()

    out: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for ang, frame_number in rows:
        jn = getattr(ang, "joint_name", None) or "unknown"
        out[jn].append({
            "frame_number": frame_number,
            "angle": getattr(ang, "angle", None),
            "angular_v": getattr(ang, "angular_v", None),
            "angular_acc": getattr(ang, "angular_acc", None)
        })
    
    for jn in out:
        out[jn].sort(key=lambda r: (r["frame_number"] or 0))
    return out