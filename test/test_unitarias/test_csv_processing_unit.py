import io
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import UploadFile
from sqlalchemy.orm import Session
from app.main import procesar_csv
from app.models import Usuario, SesionCaptura

@pytest.mark.asyncio
async def test_procesar_csv_datos_validos():
    """
    Prueba que procesar_csv maneje correctamente un archivo CSV con datos válidos.
    """
 
    csv_content = """frame_number,frame_timestamp,hips.position.x,hips.position.y,hips.position.z,left_foot.contact,right_foot.contact
1,100,1.0,2.0,3.0,True,False
2,200,1.1,2.1,3.1,False,True
"""
   
    file = UploadFile(
        filename="test_data.csv",
        file=io.BytesIO(csv_content.encode()), 
       
    )

    await file.seek(0)

 
    mock_db = AsyncMock(spec=Session)

 
    mock_current_user = MagicMock(spec=Usuario) 
    mock_current_user.usuario_id = 1 


    sesion_id = 123


    with patch('app.main.pd.read_csv') as mock_read_csv, \
         patch('app.main.io.StringIO') as mock_string_io:
    
        import pandas as pd
        mock_df = pd.DataFrame({
            'frame_number': [1, 2],
            'frame_timestamp': [100, 200],
            'hips.position.x': [1.0, 1.1],
            'hips.position.y': [2.0, 2.1],
            'hips.position.z': [3.0, 3.1],
            'left_foot.contact': [True, False],
            'right_foot.contact': [False, True]
        })
        mock_read_csv.return_value = mock_df
        mock_string_io.return_value = io.StringIO(csv_content)

      
        result = await procesar_csv(file, mock_db, mock_current_user, sesion_id)

    mock_db.commit.assert_called()

    assert result is not None 
    assert mock_db.commit.called 