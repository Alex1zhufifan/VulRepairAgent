from pydantic import BaseModel, Field, validator
from typing import Optional, List
from app.config import settings

class CodeAnalysisRequest(BaseModel):
    """代码分析请求模型"""
    
    code: str = Field(..., description="要分析的源代码")
    language: str = Field("python", description="编程语言")
    scan_depth: str = Field("basic", description="扫描深度")
    include_fixes: bool = Field(True, description="是否包含修复建议")
    
    @validator('code')
    def validate_code_length(cls, v):
        if len(v) > settings.MAX_CODE_LENGTH:
            raise ValueError(f"代码长度超过限制 ({settings.MAX_CODE_LENGTH} 字符)")
        return v
    
    @validator('language')
    def validate_language(cls, v):
        supported = ["python", "c", "cpp", "java", "javascript", "go", "rust"]
        if v.lower() not in supported:
            raise ValueError(f"不支持的语言: {v}，支持的列表: {supported}")
        return v.lower()
    
    @validator('scan_depth')
    def validate_scan_depth(cls, v):
        supported = ["basic", "deep", "comprehensive"]
        if v.lower() not in supported:
            raise ValueError(f"不支持的扫描深度: {v}，支持的列表: {supported}")
        return v.lower()