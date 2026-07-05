from fastapi import APIRouter, HTTPException
import subprocess
import tempfile
import os
import re
from typing import Dict, Any

from app.schemas.requests import ValidateRequest, ValidateResponse

router = APIRouter()

# 测试用例库
TEST_CASES = {
    "buffer_overflow": [
        {
            "name": "简单缓冲区溢出测试",
            "input": "A" * 100,
            "expected": "safe"
        }
    ],
    "command_injection": [
        {
            "name": "命令注入测试",
            "input": "test; rm -rf /",
            "expected": "filtered"
        }
    ]
}

@router.post("/", response_model=ValidateResponse)
async def validate_code(request: ValidateRequest):
    """验证修复后的代码是否安全"""
    try:
        # 这里先使用模拟验证，因为Docker需要额外配置
        result = await validate_mock(request)
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def run_in_docker(code: str, language: str) -> Dict[str, Any]:
    """在Docker沙箱中运行代码（需要安装Docker）"""
    try:
        import docker
        client = docker.from_env()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{language}', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        if language in ['c', 'cpp']:
            image = 'gcc:latest'
            if language == 'c':
                cmd = f'gcc /sandbox/code.{language} -o /sandbox/a.out && /sandbox/a.out'
            else:
                cmd = f'g++ /sandbox/code.{language} -o /sandbox/a.out && /sandbox/a.out'
        elif language == 'python':
            image = 'python:3.9-slim'
            cmd = f'python /sandbox/code.{language}'
        else:
            return {"compile_success": False, "error": f"不支持的语言: {language}"}
        
        container = client.containers.run(
            image=image,
            command=f'bash -c "{cmd}"',
            volumes={os.path.dirname(temp_file): {'bind': '/sandbox', 'mode': 'rw'}},
            mem_limit='256m',
            cpu_period=100000,
            cpu_quota=50000,
            detach=True,
            remove=True
        )
        
        result = container.wait(timeout=10)
        logs = container.logs(stdout=True, stderr=True).decode()
        
        os.unlink(temp_file)
        
        return {
            "compile_success": result['StatusCode'] == 0,
            "compile_output": logs,
            "security_issues": []
        }
        
    except ImportError:
        return {"compile_success": False, "error": "Docker模块未安装"}
    except Exception as e:
        return {"compile_success": False, "error": str(e)}

@router.post("/mock")
async def validate_mock(request: ValidateRequest):
    """模拟验证（用于前端测试）"""
    
    compile_success = True
    compile_output = ""
    security_issues = []
    
    # 精确匹配不安全的函数（避免误报 fgets）
    # 匹配独立的 gets 函数调用，而不是包含 gets 的单词
    if re.search(r'\bgets\s*\(', request.code):
        security_issues.append("发现不安全的gets函数调用")
    if re.search(r'\bstrcpy\s*\(', request.code):
        security_issues.append("发现不安全的strcpy函数调用")
    if re.search(r'\bsprintf\s*\(', request.code):
        security_issues.append("发现不安全的sprintf函数调用")
    if re.search(r'\bsystem\s*\(', request.code) and re.search(r'\binput\b', request.code):
        security_issues.append("发现可能的命令注入")
    
    # Go 语言规则
    if "exec.Command" in request.code and "+" in request.code:
        security_issues.append("发现命令注入风险（使用字符串拼接构造命令）")
    if "if err != nil" in request.code and "return err" in request.code and "klog.Error" not in request.code:
        security_issues.append("错误处理不当：返回错误前未记录日志")
    
    # 判断是否通过
    passed = compile_success and len(security_issues) == 0
    
    # 生成测试结果
    test_results = [
        {"name": "编译测试", "passed": compile_success, "output": "编译成功" if compile_success else "编译失败"},
        {"name": "安全扫描", "passed": len(security_issues) == 0,
         "output": "通过，未发现安全问题" if len(security_issues) == 0 else f"发现{len(security_issues)}个安全问题"}
    ]
    
    return ValidateResponse(
        compile_success=compile_success,
        compile_output=compile_output,
        test_results=test_results,
        security_issues=security_issues,
        passed=passed
    )