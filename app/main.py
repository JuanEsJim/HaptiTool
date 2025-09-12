import io, time, csv
from typing import List, Dict, Any
import traceback

from fastapi import FastAPI, Depends, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import SessionLocal, engine, Base
from models import AnguloArticular, ArchivoMocap, Cinematica, Contacto, Frame, Segmento, SesionCaptura, Usuario, Rol

app = FastAPI()

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

# DB dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



@app.get("/data/3d")
def get_3d_data(nombre_archivo: str, db: Session = Depends(get_db)):
    data = (
        db.query(Cinematica, Segmento.nombre, Cinematica.frame_id)  
        .join(Frame, Cinematica.frame_id == Frame.frame_id)
        .join(SesionCaptura, Frame.sesion_id == SesionCaptura.sesion_id)
        .join(ArchivoMocap, SesionCaptura.sesion_id == ArchivoMocap.sesion_id)
        .join(Segmento, Cinematica.segmento_id == Segmento.segmento_id)
        .filter(ArchivoMocap.nombre_archivo == nombre_archivo)
        .limit(500)
        .all()
    )
    return [
        {
            "x": c.pos_x,
            "y": c.pos_y,
            "z": c.pos_z,
            "segmento": nombre_segmento,
            "frame_id": frame_id  
        }
        for c, nombre_segmento, frame_id in data
    ]
@app.get("/data/2d")
def get_2d_data(nombre_archivo: str, db: Session = Depends(get_db)):
    data = (
        db.query(Cinematica)
        .join(Frame, Cinematica.frame_id == Frame.frame_id)
        .join(SesionCaptura, Frame.sesion_id == SesionCaptura.sesion_id)
        .join(ArchivoMocap, SesionCaptura.sesion_id == ArchivoMocap.archivo_id)
        .filter(ArchivoMocap.nombre_archivo == nombre_archivo)
        .limit(500)
        .all()
    )
    return [{"x": d.pos_x, "y": d.pos_y} for d in data]


@app.get("/lista_archivos/")
def lista_archivos(db: Session = Depends(get_db)):
    archivos = db.query(ArchivoMocap.nombre_archivo).distinct().all()
    return [a[0] for a in archivos if a[0] is not None]

@app.post("/upload_csv/")
async def upload_csv(file: UploadFile = File(...), db: Session = Depends(get_db)):
    contents = await file.read()
    text = contents.decode("utf-8", errors="replace")
    reader = csv.DictReader(text.splitlines())

    # Asegurar usuario mínimo
    usuario = db.query(Usuario).first()
    if not usuario:
        rol = db.query(Rol).first()
        if not rol:
            rol = Rol(nombre="default")
            db.add(rol); db.commit(); db.refresh(rol)
        usuario = Usuario(nombre="auto", email=f"auto_{int(time.time())}@local", password_hash="auto", rol_id=rol.rol_id)
        db.add(usuario); db.commit(); db.refresh(usuario)

    # Crear sesión y registro de archivo
    nueva_sesion = SesionCaptura(usuario_id=usuario.usuario_id, descripcion=f"Import {file.filename}")
    db.add(nueva_sesion); db.commit(); db.refresh(nueva_sesion)

    archivo = ArchivoMocap(sesion_id=nueva_sesion.sesion_id, nombre_archivo=file.filename, ruta_archivo=file.filename)
    db.add(archivo); db.commit(); db.refresh(archivo)

    # Preparar batches
    CHUNK = 1000
    frames_batch: List[Dict[str, Any]] = []
    cinem_batch: List[Dict[str, Any]] = []
    angulo_batch: List[Dict[str, Any]] = []
    contacto_batch: List[Dict[str, Any]] = []

    segmento_map: Dict[str, int] = {}
    frame_map: Dict[int, int] = {}  

    def normalize_seg_name(name: str) -> str:
        if not name:
            return ""
        return str(name).split('.', 1)[0].strip().lower()

    def ensure_segmento(name: str):
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

    # asegurar segmento por defecto
    default_segmento_name = "_unknown"
    default_segmento_id = ensure_segmento(default_segmento_name)
    if default_segmento_id is None:
        s_def = Segmento(nombre=default_segmento_name)
        db.add(s_def); db.commit(); db.refresh(s_def)
        default_segmento_id = s_def.segmento_id
        segmento_map[default_segmento_name] = default_segmento_id

    # construir mapeo de columnas 
    column_mappings: Dict[str, Dict[str, Any]] = {}
    for col in reader.fieldnames or []:
        col_str = str(col).strip()
        parts = col_str.split('.')
        # normalize helpers
        def seg_of(p): return p.strip().lower()

        # caso: segment.prop.axis  (3+ partes)
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

        # mapear según prop / axis
        if prop in ("position", "pos", "translation"):
           
            if axis == "x": target = "pos_x"
            elif axis == "y": target = "pos_y"
            elif axis == "z": target = "pos_z"
            else: target = None
            if target:
                column_mappings[col_str] = {"type": "cinematica", "segment": segment, "target": target}
                continue
        if prop in ("rotation", "rot", "orientation"):
            if axis == "x": target = "rot_x"
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

    
    print("column_mappings keys:", list(column_mappings.keys()))
    print("angular mappings:", {k:v for k,v in column_mappings.items() if v.get("type")=="angulo"})

    async def flush_batch():
        nonlocal frames_batch, cinem_batch, angulo_batch, contacto_batch, frame_map
        if not frames_batch:
            return

        
        db.bulk_insert_mappings(Frame, frames_batch)
        db.commit()

        
        nums = list({m["frame_number"] for m in frames_batch})
        frames_db = db.query(Frame).filter(Frame.sesion_id == nueva_sesion.sesion_id,
                                           Frame.frame_number.in_(nums)).all()
        for f in frames_db:
            frame_map[f.frame_number] = f.frame_id

        # preparar e insertar cinematica
        if cinem_batch:
            cinem_to_insert = []
            for m in cinem_batch:
                fid = frame_map.get(m["frame_number"])
                if not fid:
                    continue
                seg_id = m.get("segmento_id") or default_segmento_id
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
                    "nombre_archivo": file.filename
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
                print("DEBUG ang_to_insert sample:", ang_to_insert[:3])
                db.bulk_insert_mappings(AnguloArticular, ang_to_insert)
                db.commit()

        # contacto
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

        # limpiar batches
        frames_batch = []
        cinem_batch = []
        angulo_batch = []
        contacto_batch = []

    
    for row in reader:
        
        try:
            fnum = int(row.get("frame_number") or row.get("frame_number".lower()) or 0)
        except Exception:
            continue

        frames_batch.append({
            "sesion_id": nueva_sesion.sesion_id,
            "frame_number": fnum,
            "timestamp_ms": int(row.get("frame_timestamp") or row.get("timestamp_ms") or 0)
        })

        
        seg_values: Dict[str, Dict[str, Any]] = {} 

        
        contact_vals: Dict[str, Dict[str, Any]] = {}  
        ang_vals: Dict[str, Dict[str, Any]] = {}      

        
        for col_name, meta in column_mappings.items():
            if col_name not in row:
                continue
            raw = row.get(col_name)
            if raw is None or raw == "":
                continue
            
            if meta.get("meta") == "frame":
                continue
            try:
                mtype = meta.get("type")
                if mtype == "cinematica":
                    if meta.get("segment"):
                        seg = normalize_seg_name(meta["segment"])
                    else:
                        seg = normalize_seg_name(row.get("segmento") or row.get("segment_name") or "") or default_segmento_name
                    if seg not in seg_values:
                        seg_values[seg] = {"pos_x": None, "pos_y": None, "pos_z": None, "rot_w": float(row.get("rot_w") or 0), "rot_x": None, "rot_y": None, "rot_z": None}
                    target = meta.get("target")
                    if target and (target.startswith("pos_") or target.startswith("rot_")):
                        seg_values[seg][target] = float(raw)
                elif mtype == "contact":
                    seg = normalize_seg_name(meta.get("segment") or row.get("segmento") or "")
                    if not seg:
                        seg = default_segmento_name
                    side = meta.get("side") or ""
                    
                    s = side.lower()
                    left_keys = ("left","l","left_foot","leftfoot","l_foot")
                    right_keys = ("right","r","right_foot","rightfoot","r_foot")
                    if seg not in contact_vals:
                        contact_vals[seg] = {"left": None, "right": None}
                    val = None
                    try:
                        val = bool(int(raw))
                    except Exception:
                       
                        if str(raw).lower() in ("true","1","yes","y"):
                            val = True
                        elif str(raw).lower() in ("false","0","no","n"):
                            val = False
                    if s in left_keys:
                        contact_vals[seg]["left"] = val
                    elif s in right_keys:
                        contact_vals[seg]["right"] = val
                    else:
                       
                        if "left" in seg:
                            contact_vals[seg]["left"] = val
                        elif "right" in seg:
                            contact_vals[seg]["right"] = val
                        else:
                            
                            contact_vals[seg]["right"] = val
                elif mtype == "angulo":
                    seg = normalize_seg_name(meta.get("segment") or row.get("segmento") or "")
                    if not seg:
                        seg = default_segmento_name
                    if seg not in ang_vals:
                        
                        ang_vals[seg] = {"angle": None, "angular_v": None, "angular_acc": None}
                    target = meta.get("target")
                    try:
                        if target == "angle":
                            ang_vals[seg]["angle"] = float(raw)
                        elif target == "angular_v":
                            ang_vals[seg]["angular_v"] = float(raw)
                        elif target == "angular_acc":
                            ang_vals[seg]["angular_acc"] = float(raw)
                    except Exception:
                        continue
            except Exception:
                continue

        
        for seg_name, vals in seg_values.items():
            seg_id = ensure_segmento(seg_name) or default_segmento_id
            cinem_batch.append({
                "frame_number": fnum,
                "segmento_id": seg_id,
                "pos_x": vals.get("pos_x"),
                "pos_y": vals.get("pos_y"),
                "pos_z": vals.get("pos_z"),
                "rot_w": vals.get("rot_w", 0),
                "rot_x": vals.get("rot_x", 0),
                "rot_y": vals.get("rot_y", 0),
                "rot_z": vals.get("rot_z", 0),
            })

        
        for seg_name, vals in ang_vals.items():
            try:
                angulo_batch.append({
                    "frame_number": fnum,
                    "joint_name": seg_name,
                    "angle": vals.get("angle") if vals.get("angle") is not None else None,
                    "angular_v": vals.get("angular_v") if vals.get("angular_v") is not None else None,
                    "angular_acc": vals.get("angular_acc") if vals.get("angular_acc") is not None else None
                })
            except Exception:
                continue

       
        combined_left = None
        combined_right = None
        for seg_name, vals in contact_vals.items():
            if "foot" in seg_name or "foot" in seg_name.replace("_",""):
                if combined_left is None and vals.get("left") is not None:
                    combined_left = vals.get("left")
                if combined_right is None and vals.get("right") is not None:
                    combined_right = vals.get("right")
            else:
                
                if combined_left is None and vals.get("left") is not None:
                    combined_left = vals.get("left")
                if combined_right is None and vals.get("right") is not None:
                    combined_right = vals.get("right")
        if combined_left is not None or combined_right is not None:
            contacto_batch.append({
                "frame_number": fnum,
                "left_foot_contact": combined_left,
                "right_foot_contact": combined_right
            })

        
        if len(frames_batch) >= CHUNK:
            await flush_batch()

   
    await flush_batch()

    return JSONResponse({"status": "ok", "sesion_id": nueva_sesion.sesion_id})

@app.get("/data/angles")
def get_angles(nombre_archivo: str, db: Session = Depends(get_db)):
   
    rows = db.query(AnguloArticular, Frame.frame_number).\
        join(Frame, AnguloArticular.frame_id == Frame.frame_id).\
        join(ArchivoMocap, ArchivoMocap.sesion_id == Frame.sesion_id).\
        filter(ArchivoMocap.nombre_archivo == nombre_archivo).all()

    out: Dict[str, List[Dict[str, Any]]] = {}
    for ang, frame_number in rows:
        jn = getattr(ang, "joint_name", None) or "unknown"
        if jn not in out:
            out[jn] = []
        out[jn].append({
            "frame_number": frame_number,
            "angle": getattr(ang, "angle", None),
            "angular_v": getattr(ang, "angular_v", None),
            "angular_acc": getattr(ang, "angular_acc", None)
        })

    
    for jn in out:
        out[jn].sort(key=lambda r: (r["frame_number"] or 0))
    return out

