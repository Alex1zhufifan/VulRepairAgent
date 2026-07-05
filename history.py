from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
import json
from typing import Optional

from app.models.user import get_db, User
from app.models.history import History, get_history_db
from app.schemas.history import HistoryCreate, HistoryResponse, HistoryListResponse
from app.api.v1.endpoints.auth import get_current_user

router = APIRouter(prefix="/history", tags=["历史记录"])

@router.post("/save")
async def save_history(
    history_data: HistoryCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """保存历史记录"""
    history = History(
        user_id=current_user.id,
        type=history_data.type,
        language=history_data.language,
        original_code=history_data.original_code,
        result_code=history_data.result_code,
        changes=json.dumps(history_data.changes, ensure_ascii=False) if history_data.changes else None
    )
    db.add(history)
    db.commit()
    db.refresh(history)
    return {"success": True, "id": history.id}

@router.get("/list", response_model=HistoryListResponse)
async def get_history_list(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
    type: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取历史记录列表"""
    query = db.query(History).filter(History.user_id == current_user.id)
    
    if type:
        query = query.filter(History.type == type)
    
    total = query.count()
    items = query.order_by(desc(History.created_at)).offset((page - 1) * page_size).limit(page_size).all()
    
    result_items = []
    for item in items:
        changes = None
        if item.changes:
            try:
                changes = json.loads(item.changes)
            except:
                changes = []
        
        result_items.append({
            "id": item.id,
            "type": item.type,
            "language": item.language,
            "original_code": item.original_code[:500] + ("..." if len(item.original_code) > 500 else ""),
            "result_code": item.result_code[:500] + ("..." if len(item.result_code) > 500 else "") if item.result_code else None,
            "changes": changes,
            "created_at": item.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })
    
    return HistoryListResponse(total=total, items=result_items)

@router.get("/detail/{history_id}")
async def get_history_detail(
    history_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取历史记录详情"""
    history = db.query(History).filter(
        History.id == history_id,
        History.user_id == current_user.id
    ).first()
    
    if not history:
        raise HTTPException(status_code=404, detail="记录不存在")
    
    changes = None
    if history.changes:
        try:
            changes = json.loads(history.changes)
        except:
            changes = []
    
    return {
        "id": history.id,
        "type": history.type,
        "language": history.language,
        "original_code": history.original_code,
        "result_code": history.result_code,
        "changes": changes,
        "created_at": history.created_at.strftime("%Y-%m-%d %H:%M:%S")
    }

@router.delete("/delete/{history_id}")
async def delete_history(
    history_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除历史记录"""
    history = db.query(History).filter(
        History.id == history_id,
        History.user_id == current_user.id
    ).first()
    
    if not history:
        raise HTTPException(status_code=404, detail="记录不存在")
    
    db.delete(history)
    db.commit()
    return {"success": True}