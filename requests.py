from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class AnalyzeRequest(BaseModel):
    """漏洞分析请求"""
    code: str = Field(..., description="要分析的代码", max_length=10000)
    language: str = Field("c", description="编程语言：c/cpp/python/java/go")
    filename: Optional[str] = None

class AnalyzeResponse(BaseModel):
    """漏洞分析响应"""
    vulnerability_type: str
    confidence: float
    affected_lines: List[int]
    root_cause: str
    description: str
    cwe_id: str

class GenerateRequest(BaseModel):
    """修复生成请求"""
    code: str = Field(..., description="漏洞代码")
    language: str = "c"
    vulnerability_type: Optional[str] = None
    use_few_shot: bool = True
    template_version: str = "v2.0"

class GenerateResponse(BaseModel):
    """修复生成响应"""
    original_code: str
    fixed_code: str
    explanation: str
    changes_made: List[Dict[str, Any]]
    confidence: float

class ValidateRequest(BaseModel):
    """验证请求"""
    code: str
    language: str
    test_case_id: Optional[str] = None

class ValidateResponse(BaseModel):
    """验证响应"""
    compile_success: bool
    compile_output: Optional[str] = None
    test_results: List[Dict[str, Any]]
    security_issues: List[str]
    passed: bool