from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class HistoryCreate(BaseModel):
    type: str  # analyze, generate, validate
    language: str
    original_code: str
    result_code: Optional[str] = None
    changes: Optional[List[Dict[str, Any]]] = None

class HistoryResponse(BaseModel):
    id: int
    type: str
    language: str
    original_code: str
    result_code: Optional[str]
    changes: Optional[List[Dict[str, Any]]]
    created_at: str

class HistoryListResponse(BaseModel):
    total: int
    items: List[HistoryResponse]