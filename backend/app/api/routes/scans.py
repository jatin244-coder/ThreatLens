"""Scan creation and retrieval endpoints."""

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import Response

from app.core.config import get_settings
from app.schemas.scans import AnalysisResponse, ErrorResponse, ScanCreateRequest, ScanHistoryResponse, ScanResponse
from app.services.analysis_service import get_scan_analysis
from app.services.report_service import (
    ReportGenerationError,
    ReportLabUnavailableError,
    generate_scan_report,
    report_filename,
)
from app.services.scan_service import (
    InvalidHostnameError,
    ScanExecutionError,
    ScanInProgressError,
    create_scan,
    get_scan,
    list_scans,
    run_stored_scan,
)


router = APIRouter(prefix="/scans", tags=["scans"])


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorResponse},
        422: {"description": "Validation error"},
        500: {"model": ErrorResponse},
    },
)
async def queue_scan(payload: ScanCreateRequest) -> ScanResponse:
    """Validate and persist a scan request in the queued state."""
    try:
        return create_scan(payload, get_settings().database_url)
    except PermissionError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
    except InvalidHostnameError as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)) from error


@router.get(
    "",
    response_model=ScanHistoryResponse,
    responses={
        422: {"description": "Validation error"},
        500: {"model": ErrorResponse},
    },
)
async def list_scan_history(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> ScanHistoryResponse:
    """Return newest-first dashboard summaries without finding evidence."""
    return list_scans(get_settings().database_url, limit, offset)


@router.get(
    "/{scan_id}/analysis",
    response_model=AnalysisResponse,
    responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
)
async def retrieve_scan_analysis(scan_id: str) -> AnalysisResponse:
    """Return deterministic analysis generated from the current findings."""
    analysis = get_scan_analysis(scan_id, get_settings().database_url)
    if analysis is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return analysis


@router.get(
    "/{scan_id}/report",
    response_class=Response,
    responses={
        200: {
            "description": "PDF security report",
            "content": {"application/pdf": {"schema": {"type": "string", "format": "binary"}}},
        },
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)
async def download_scan_report(scan_id: str) -> Response:
    """Return a read-only PDF generated from the stored scan and findings."""
    try:
        report = generate_scan_report(scan_id, get_settings().database_url)
    except ReportLabUnavailableError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PDF report generation is unavailable",
        ) from error
    except ReportGenerationError as error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(error)) from error
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return Response(
        content=report,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{report_filename(scan_id)}"'},
    )


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
)
async def retrieve_scan(scan_id: str) -> ScanResponse:
    """Return a stored scan record by ID."""
    scan = get_scan(scan_id, get_settings().database_url)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return scan


@router.post(
    "/{scan_id}/run",
    response_model=ScanResponse,
    responses={
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"description": "Validation error"},
        500: {"model": ErrorResponse},
    },
)
async def run_authorized_scan(scan_id: str) -> ScanResponse:
    """Run the bounded scanner for an existing authorized scan record."""
    try:
        return_value = run_stored_scan(scan_id, get_settings().database_url)
    except ScanInProgressError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
    except ScanExecutionError as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="scan execution failed",
        ) from error
    if return_value is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return return_value
