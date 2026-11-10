import json

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.deps import integration_token
from app.models import IntegrationToken, Project
from app.schemas import IngestPayload, IngestResponse
from app.services.ingest import EXIT_CODES, process_ingest

router = APIRouter(prefix="/api/v1", tags=["ingest"])


@router.post("/ingest", response_model=IngestResponse)
async def ingest(request: Request, tok: IntegrationToken = Depends(integration_token), db: Session = Depends(get_db)):
    """Receive scanner reports from the pipeline and return the decision in the same response."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > settings.max_report_bytes:
        raise HTTPException(413, f"Payload larger than {settings.max_report_bytes} bytes")
    body = await request.body()
    if len(body) > settings.max_report_bytes:
        raise HTTPException(413, f"Payload larger than {settings.max_report_bytes} bytes")
    try:
        payload = IngestPayload.model_validate(json.loads(body))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(400, "Body is not valid JSON") from exc
    except ValidationError as exc:
        errs = [f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}" for e in exc.errors()[:10]]
        raise HTTPException(422, {"message": "Invalid payload", "errors": errs}) from exc

    project = db.get(Project, tok.project_id)
    outcome = process_ingest(db, project, tok, payload)
    db.commit()
    dec = outcome.decision
    return IngestResponse(
        run_id=outcome.run.id,
        decision=dec.result,
        exit_code=EXIT_CODES[dec.result],
        replay=outcome.replay,
        policy_version=dec.policy_version,
        reasons=dec.reasons,
        summary=dec.summary,
        dashboard_url=f"{settings.base_url.rstrip('/')}/runs/{outcome.run.id}",
    )
