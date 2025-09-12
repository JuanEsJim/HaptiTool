from fastapi import FastAPI, UploadFile, File, Depends
from sqlalchemy.orm import Session
import pandas as pd
import shutil, os
from database import SessionLocal
from models import ArchivoMocap, Frame, Cinematica, AnguloArticular

app = FastAPI()

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Conexión a la BD
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/upload_csv/")
async def upload_csv(
    sesion_id: int, 
    file: UploadFile = File(...), 
    db: Session = Depends(get_db)
):
    # 1. Guardar archivo en disco
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 2. Registrar archivo en BD
    archivo = ArchivoMocap(
        sesion_id=sesion_id,
        nombre_archivo=file.filename,
        ruta_archivo=file_path
    )
    db.add(archivo)
    db.commit()
    db.refresh(archivo)

    # 3. Procesar CSV con pandas
    df = pd.read_csv(file_path)

    for i, row in df.iterrows():
        # Guardar frame
        frame = Frame(sesion_id=sesion_id, frame_number=i, timestamp_ms=row["frame_timestamp"])
        db.add(frame)
        db.commit()
        db.refresh(frame)

        # Guardar ejemplo de cinemática
        db.add(Cinematica(
            frame_id=frame.frame_id,
            segmento_id="hips",
            pos_x=row["hips.position.x"],
            pos_y=row["hips.position.y"],
            pos_z=row["hips.position.z"],
            rot_w=row["hips.rotation.w"],
            rot_x=row["hips.rotation.x"],
            rot_y=row["hips.rotation.y"],
            rot_z=row["hips.rotation.z"]
        ))

        # Guardar ejemplo de ángulo articular
        db.add(AnguloArticular(
            frame_id=frame.frame_id,
            joint_name="KneeFlexExtR",
            angle=row["KneeFlexExtR.angle"],
            angular_v=row["KneeFlexExtR.angular_v"]
        ))

    db.commit()

    return {"status": "ok", "archivo_id": archivo.archivo_id, "mensaje": "Archivo subido y procesado"}
