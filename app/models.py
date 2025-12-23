from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class DomainResult(BaseModel):
    domain: str
    mx_records: str = ""
    spf_record: str = ""
    dmarc_record: str = ""
    dmarc_policy: str = ""
    has_dmarc_policy: bool = False
    dmarc_ruf_email: str = ""
    has_website: bool = False
    a_record: str = ""
    www_cname: str = ""
    www_points_to_main: bool = False
    tech_contact_email: str = ""
    error: str = ""

class AnalysisRequest(BaseModel):
    domains: List[str]

class AnalysisResponse(BaseModel):
    results: List[DomainResult]
    summary: dict
    timestamp: datetime