from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from typing import List, Optional
import json
import os
import csv
import io

from .models import database, history
from .schemas import validation as schemas
from .services.validator import ISOValidator

# Initialize database
database.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="ISO 20022 Validation API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"]
)

validator = ISOValidator()

@app.post("/validate", response_model=schemas.ValidationResponse)
async def validate_message(
    request: schemas.ValidationRequest,
    db: Session = Depends(database.get_db)
):
    report = await validator.validate(request.xml_content, request.mode, request.message_type)
    report_dict = report.to_dict()
    
    if request.store_in_history:
        db_history = history.ValidationHistory(
            validation_id=report_dict["validation_id"],
            message_type=report_dict["message"],
            status=report_dict["status"],
            total_errors=report_dict["errors"],
            total_warnings=report_dict["warnings"],
            execution_time_ms=report_dict["total_time_ms"],
            report_json=report_dict,
            original_message=request.xml_content
        )
        db.add(db_history)
        db.commit()
    
    return report_dict

@app.post("/validate-file", response_model=schemas.ValidationResponse)
async def validate_file(
    file: UploadFile = File(...),
    mode: str = Form("Full 1-5"),
    message_type: str = Form("Auto-detect"),
    store_in_history: bool = Form(True),
    db: Session = Depends(database.get_db)
):
    # Step 2: File Type Validation
    if not file.filename.lower().endswith('.xml'):
        # We'll let the validator handle the error reporting in a consistent format
        # but technically this is where we reject the file extension.
        pass
    
    content = await file.read()
    xml_content = content.decode("utf-8")
    
    report = await validator.validate(xml_content, mode, message_type, filename=file.filename)
    report_dict = report.to_dict()
    
    if store_in_history:
        try:
            db_history = history.ValidationHistory(
                validation_id=report_dict["validation_id"],
                message_type=report_dict["message"],
                status=report_dict["status"],
                total_errors=report_dict["errors"],
                total_warnings=report_dict["warnings"],
                execution_time_ms=report_dict["total_time_ms"],
                report_json=report_dict,
                original_message=xml_content
            )
            db.add(db_history)
            db.commit()
        except Exception as db_err:
            print(f"Warning: Failed to save history record: {db_err}")
            db.rollback()
    
    return report_dict

@app.get("/history", response_model=List[schemas.HistorySummary])
def get_history(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db)):
    try:
        results = db.query(history.ValidationHistory).order_by(history.ValidationHistory.timestamp.desc()).offset(skip).limit(limit).all()
        return results
    except Exception as e:
        print(f"Error fetching history: {e}")
        return []

@app.get("/history/export")
def export_history(db: Session = Depends(database.get_db)):
    try:
        results = db.query(history.ValidationHistory).order_by(history.ValidationHistory.timestamp.desc()).all()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(["Timestamp", "Validation ID", "Message Type", "Status", "Errors", "Warnings", "Duration (ms)"])
        
        for row in results:
            ts_str = row.timestamp.strftime("%Y-%m-%d %H:%M:%S") if row.timestamp else ""
            writer.writerow([
                f"{ts_str} (UTC)",
                row.validation_id,
                row.message_type,
                row.status,
                row.total_errors,
                row.total_warnings,
                row.execution_time_ms
            ])
        
        csv_content = output.getvalue()
        output.close()
        
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=iso20022_audit_trail.csv",
                "Access-Control-Expose-Headers": "Content-Disposition"
            }
        )
    except Exception as e:
        print(f"EXPORT ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")

@app.get("/history/{validation_id}")
def get_history_detail(validation_id: str, db: Session = Depends(database.get_db)):
    result = db.query(history.ValidationHistory).filter(history.ValidationHistory.validation_id == validation_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="Validation not found")
    return {
        "report": result.report_json,
        "original_message": result.original_message
    }

@app.delete("/history/{validation_id}")
def delete_history_record(validation_id: str, db: Session = Depends(database.get_db)):
    result = db.query(history.ValidationHistory).filter(history.ValidationHistory.validation_id == validation_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="Validation not found")
    db.delete(result)
    db.commit()
    return {"message": "Record deleted successfully"}

@app.get("/messages", response_model=List[str])
def get_messages():
    return validator.get_supported_messages()

# --- GLOBALLY READY: Serve Frontend ---
# This allows the backend to serve the frontend UI in a production environment
frontend_path = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(frontend_path):
    app.mount("/ui", StaticFiles(directory=frontend_path, html=True), name="ui")
    
    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        # If it looks like an API call or file with extension, don't interfere
        if full_path.startswith("api") or "." in full_path:
            return None # standard fastapi behavior
        
        # Otherwise, serve index.html for SPA routing
        index_file = os.path.join(frontend_path, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"status": "ok", "info": "Frontend build folder found but index.html missing."}

@app.get("/")
def health_check():
    # If frontend exists, redirect to UI
    if os.path.exists(frontend_path):
        return FileResponse(os.path.join(frontend_path, "index.html"))
    return {"status": "ok", "service": "ISO 20022 Validator", "info": "Run frontend on port 4200 or build it into backend/app/static"}
