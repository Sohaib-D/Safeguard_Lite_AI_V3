from fastapi import APIRouter, Depends, Body, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse
from typing import Any, Dict, Optional
from pydantic import BaseModel, field_validator
import uuid
import re

from backend.dependencies.auth import get_current_user
from backend.network.active_scanner import ActiveScanner
from backend.network.deep_scanner import run_deep_scan
from backend.services.security_intelligence import SecurityIntelligence
from backend.services.report_generator import ReportGenerator

router = APIRouter(prefix="/recon", tags=["Recon"])

scan_jobs: Dict[str, dict] = {}

class DeepScanRequest(BaseModel):
    target: str
    quick_scan: bool = True

    @field_validator('target')
    @classmethod
    def validate_target(cls, v):
        v_stripped = v.strip()
        if not v_stripped:
            raise ValueError("Target cannot be empty")
        
        pattern = r'^(https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost|(?:[0-9]{1,3}\.){3}[0-9]{1,3})(:[0-9]{1,5})?(/.*)?$'
        if not re.match(pattern, v_stripped):
            raise ValueError("Target must be a valid IP address, domain, or URL")
        return v_stripped

async def background_deep_scan(scan_id: str, target: str, quick: bool):
    try:
        result = await run_deep_scan(target, quick)
        
        scan_jobs[scan_id]["status"] = "complete"
        scan_jobs[scan_id]["progress_percent"] = 100
        scan_jobs[scan_id]["result"] = result
    except Exception as e:
        scan_jobs[scan_id]["status"] = "failed"
        scan_jobs[scan_id]["error"] = str(e)


@router.post("/scan", tags=["Recon"])
async def active_scan(target: str = Body(..., embed=True), current_user: Any = Depends(get_current_user)):
    scanner = ActiveScanner()
    results = await scanner.scan_target(target)
    return results


@router.post("/deep-scan", tags=["Deep Security Scan"])
async def deep_scan_target(
    request: DeepScanRequest, 
    current_user: Any = Depends(get_current_user)
):
    """Run a deep scan synchronously and return full results."""
    try:
        result = await run_deep_scan(request.target, request.quick_scan)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.get("/scan-status/{scan_id}", tags=["Deep Security Scan"])
async def get_scan_status(scan_id: str, current_user: Any = Depends(get_current_user)):
    if scan_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    
    job = scan_jobs[scan_id]
    return {
        "scan_id": job["scan_id"],
        "status": job["status"],
        "progress_percent": job["progress_percent"],
        "result": job["result"],
        "error": job.get("error")
    }


@router.post("/analyze-scan", tags=["Deep Security Scan"])
async def analyze_scan_result(
    payload: dict = Body(...),
    current_user: Any = Depends(get_current_user),
):
    intel = SecurityIntelligence()
    scan_result = payload.get("scan_result", {})
    
    if not scan_result:
        raise HTTPException(status_code=400, detail="scan_result is required in payload")
    
    analysis = await intel.analyze_scan(scan_result)
    client_angle = await intel.assess_for_client_offering(analysis)
    report_data = await intel.generate_pdf_report_data(scan_result, analysis)
    
    return {
        "analysis": analysis,
        "client_offering": client_angle,
        "report_data": report_data,
    }


@router.post("/export-report", tags=["Deep Security Scan"])
async def export_html_report(
    payload: dict = Body(...),
    current_user: Any = Depends(get_current_user),
):
    gen = ReportGenerator()
    html_content = gen.generate_html_report(
        target=payload.get("target", "Unknown"),
        scan_result=payload.get("scan_result", {}),
        analysis=payload.get("analysis", {}),
    )
    return HTMLResponse(content=html_content)
