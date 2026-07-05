from fastapi import APIRouter, HTTPException
from typing import List
import logging
import json
import re
import time

from app.schemas.requests import AnalyzeRequest, AnalyzeResponse
from app.models.ml_service import model_service

router = APIRouter()
logger = logging.getLogger(__name__)

def detect_actual_language(code: str) -> str:
    """根据代码内容推断实际编程语言（只检测系统支持的语言）"""
    
    # Python 特征
    if 'def ' in code :
        return "python"
    if 'import ' in code and ('from ' in code or 'as ' in code):
        return "python"
    if 'print(' in code or 'input(' in code:
        return "python"
    if 'if __name__' in code:
        return "python"
    
    # Java 特征
    if 'public class ' in code and '{' in code:
        return "java"
    if 'public static void main' in code:
        return "java"
    if 'System.out.println' in code or 'System.out.print' in code:
        return "java"
    if 'String[] args' in code:
        return "java"
    
    # Go 特征
    if 'package main' in code and 'func main()' in code:
        return "go"
    if 'func ' in code and '{' in code and 'return ' in code:
        return "go"
    if 'err != nil' in code:
        return "go"
    if 'StabilityLevel:' in code or 'DeprecatedVersion:' in code:
        return "go"
    
    # C 特征
    if 'int main(' in code or 'void main(' in code:
        return "c"
    if 'printf(' in code or 'scanf(' in code:
        return "c"
    if 'char ' in code and ';' in code:
        return "c"
    
    # C++ 特征
    if 'int main(' in code and 'std::' in code:
        return "cpp"
    if 'cout <<' in code or 'cin >>' in code:
        return "cpp"
    if 'class ' in code and 'public:' in code:
        return "cpp"
    
    # JavaScript 特征
    if 'function ' in code and '{' in code:
        return "javascript"
    if 'console.log' in code:
        return "javascript"
    if 'const ' in code and '=' in code and ';' in code:
        return "javascript"
    if '=>' in code:
        return "javascript"

        # 如果代码包含常见编程符号，但无法确定具体语言，根据用户选择返回
    # 这种情况返回 None，让用户选择来决定
    if any(symbol in code for symbol in ['{', '}', '(', ')', ';', '=', ':']):
        return None  # 无法确定具体语言，交给用户选择
    
    return None
# 配置常量
MAX_CODE_LENGTH = 10000
SUPPORTED_LANGUAGES = ["python", "c", "cpp", "java", "go", "javascript", "typescript", "rust"]

# ========== CWE 检测规则配置 ==========
CWE_RULES = {
    "CWE-20": {
        "patterns": [r'eval\s*\(', r'exec\s*\('],
        "description": "输入验证不当",
        "message": "使用了 eval() 或 exec() 执行动态代码，可能导致代码注入攻击"
    },
    "CWE-22": {
        "patterns": [r'\.\./', r'os\.path\.join\s*\([^)]*\+'],
        "description": "路径遍历",
        "message": "路径拼接包含 '../' 模式，可能导致目录遍历攻击"
    },
    "CWE-78": {
        "patterns": [r'os\.system\s*\([^)]*\+', r'system\s*\([^)]*\+', r'shell\s*=\s*True'],
        "description": "命令注入",
        "message": "使用字符串拼接构造系统命令，攻击者可注入恶意命令"
    },
    "CWE-89": {
        "patterns": [r'SELECT.*\+', r'INSERT.*\+', r'f".*\{.*\}.*"', r'\.format\('],
        "description": "SQL注入",
        "message": "使用字符串拼接构造 SQL 查询，存在 SQL 注入风险"
    },
    "CWE-117": {
        "patterns": [r'logging\.\w+\s*\([^)]*\+', r'logger\.\w+\s*\([^)]*\+'],
        "description": "日志注入",
        "message": "用户输入直接写入日志，可能导致日志注入攻击"
    },
    "CWE-120": {
        "patterns": [r'strcpy\s*\(', r'strcat\s*\(', r'sprintf\s*\(', r'gets\s*\('],
        "description": "缓冲区溢出",
        "message": "使用了不安全的字符串函数，可能导致缓冲区溢出"
    },
    "CWE-190": {
        "patterns": [r'\*\s*[a-zA-Z_]+\s*\*'],
        "description": "整数溢出",
        "message": "整数乘法运算可能导致溢出"
    },
    "CWE-200": {
        "patterns": [r'password\s*=\s*["\'][^"\']+["\']', r'secret\s*=\s*["\']'],
        "description": "信息泄露",
        "message": "代码中硬编码了密码或密钥"
    },
    "CWE-209": {
        "patterns": [r'print\s*\(.*traceback', r'stacktrace'],
        "description": "错误信息泄露",
        "message": "错误信息包含堆栈跟踪，可能泄露敏感信息"
    },
    "CWE-252": {
        "patterns": [r'fopen\s*\([^)]+\)\s*;\s*\n\s*[^i]'],
        "description": "未检查返回值",
        "message": "fopen 返回值未检查，可能导致空指针使用"
    },
    "CWE-284": {
        "patterns": [r'chmod\s*\([^,]+,\s*777', r'AllowAll'],
        "description": "权限管理不当",
        "message": "使用了过于宽松的权限设置 (777)"
    },
    "CWE-327": {
        "patterns": [r'MD5\s*\(', r'SHA1\s*\(', r'DES\s*\('],
        "description": "不安全的加密算法",
        "message": "使用了已破解的加密算法 (MD5/SHA1/DES)"
    },
    "CWE-362": {
        "patterns": [r'threading\.Lock\s*\(\).*?\n.*\.release', r'synchronized'],
        "description": "竞态条件",
        "message": "可能存在线程安全问题"
    },
    "CWE-400": {
        "patterns": [r'while\s+True:', r'for\s+.*\s+in\s+range\(\d{7}\)'],
        "description": "资源消耗",
        "message": "可能存在无限循环或超大循环"
    },
    "CWE-416": {
    "patterns": [r'free\s*\([^)]+\);\s*[^\n]*'],  # 去掉 \1
    "description": "释放后使用",
    "message": "free 后继续使用指针，可能导致释放后使用漏洞"
},
    "CWE-476": {
    "patterns": [r'if\s*\([^)]+\)\s*\{[^}]*\w+\s*->'],  # 修复
    "description": "空指针解引用",
    "message": "未检查指针是否为 NULL 就直接访问，可能导致空指针解引用"
},
    "CWE-477": {
        "patterns": [r'DeprecatedVersion:', r'@deprecated'],
        "description": "废弃函数使用",
        "message": "使用了已废弃的 API"
    },
    "CWE-480": {
        "patterns": [r'if\s*\([^=]*=[^=]'],
        "description": "操作符混淆",
        "message": "条件判断中可能误用赋值运算符"
    },
    "CWE-611": {
        "patterns": [r'XMLReader', r'SAXParser', r'DocumentBuilder'],
        "description": "XXE攻击",
        "message": "XML 解析器未禁用外部实体，存在 XXE 风险"
    },
    "CWE-665": {
        "patterns": [r'=\s*NULL\s*;'],
        "description": "初始化不当",
        "message": "变量可能未正确初始化"
    },
    "CWE-754": {
        "patterns": [r'if\s*\([^)]+\)\s*{[^}]*\n\s*return'],
        "description": "异常检查不当",
        "message": "错误处理可能不完整"
    },
    "CWE-770": {
        "patterns": [r'malloc\s*\([^)]+\)', r'new\s+[a-zA-Z_]+\['],
        "description": "资源分配无限制",
        "message": "动态内存分配未检查大小限制"
    },
    "CWE-1104": {
        "patterns": [r'version:\s*["\']?[0-9]+\.[0-9]+\.[0-9]+'],
        "description": "过时组件使用",
        "message": "使用了可能存在漏洞的旧版本组件"
    }
}
def validate_analysis_result(analysis: dict) -> bool:
    """验证分析结果格式是否正确"""
    required_fields = ["vulnerability_type", "confidence", "affected_lines", "root_cause", "description", "cwe_id"]
    
    for field in required_fields:
        if field not in analysis:
            return False
    
    try:
        confidence = float(analysis["confidence"])
        if confidence < 0 or confidence > 1:
            return False
    except (ValueError, TypeError):
        return False
    
    if not isinstance(analysis["affected_lines"], list):
        return False
    
    for line in analysis["affected_lines"]:
        if not isinstance(line, int):
            return False
    
    if not re.match(r'^CWE-\d+$', analysis["cwe_id"]):
        return False
    
    return True

def check_syntax_error(code: str, language: str) -> dict:
    """检查代码语法错误"""
    language = language.lower()
    
    # Python 语法检查
    if language == "python":
        try:
            compile(code, '<string>', 'exec')
            return {"has_error": False, "error_message": None, "error_line": None}
        except SyntaxError as e:
            return {
                "has_error": True,
                "error_message": f"语法错误: {e.msg}",
                "error_line": e.lineno,
                "error_text": e.text
            }
    
    # C/C++ 语法检查（简单检查常见语法问题）
    elif language in ["c", "cpp"]:
        # 检查括号匹配
        if code.count('(') != code.count(')'):
            return {"has_error": True, "error_message": "括号不匹配", "error_line": None}
        # 检查大括号匹配
        if code.count('{') != code.count('}'):
            return {"has_error": True, "error_message": "大括号不匹配", "error_line": None}
       
    return {"has_error": False, "error_message": None, "error_line": None}


def is_safe_system_call(code_line: str) -> bool:
    """判断 os.system 调用是否安全"""
    # 提取 system 调用的参数
    import re
    
    # 匹配 os.system("xxx") 或 system("xxx")
    pattern = r'(?:os\.)?system\s*\(\s*["\']([^"\']+)["\']\s*\)'
    match = re.search(pattern, code_line)
    
    if match:
        # 参数是硬编码字符串，没有变量拼接
        return True
    
    # 检查是否有变量拼接
    if '+' in code_line or '%' in code_line or 'f"' in code_line or "f'" in code_line:
        return False
    
    # 检查是否有变量传入
    if re.search(r'system\s*\(\s*\w+\s*\)', code_line):
        return False
    
    return True


def detect_command_injection(code: str) -> List[dict]:
    """检测命令注入漏洞 - 改进版，区分安全调用和危险调用"""
    vulnerabilities = []
    lines = code.split('\n')
    
    for i, line in enumerate(lines, 1):
        # 只检测 os.system 和 system 调用
        if 'os.system' in line or re.search(r'\bsystem\s*\(', line):
            # 判断是否安全
            if is_safe_system_call(line):
                # 安全调用（硬编码命令），不报警
                continue
            else:
                # 危险调用（有变量拼接或用户输入）
                vulnerabilities.append({
                    "vulnerability_type": "命令注入",
                    "confidence": 0.90,
                    "affected_lines": [i],
                    "root_cause": "用户输入直接传递给 system 函数，存在命令注入风险",
                    "description": "使用字符串拼接构造系统命令，攻击者可注入恶意命令",
                    "cwe_id": "CWE-78"
                })
        
        # subprocess 危险模式：只有 shell=True 才报警
        if 'subprocess.run' in line or 'subprocess.Popen' in line:
            if 'shell=True' in line:
                vulnerabilities.append({
                    "vulnerability_type": "命令注入",
                    "confidence": 0.90,
                    "affected_lines": [i],
                    "root_cause": "subprocess 使用了 shell=True，存在命令注入风险",
                    "description": "shell=True 会启用 shell 解析，用户输入可能被解释为额外命令",
                    "cwe_id": "CWE-78"
                })
            # 参数列表方式（如 ["ping", ip]）是安全的，不报警
    
    return vulnerabilities


def detect_sql_injection(code: str) -> List[dict]:
    """检测 SQL 注入漏洞 - 改进版"""
    vulnerabilities = []
    lines = code.split('\n')
    sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE"]
    
    for i, line in enumerate(lines, 1):
        # 只检测包含 SQL 关键字的行
        if not any(keyword in line.upper() for keyword in sql_keywords):
            continue
        
        # 参数化查询是安全的，不报警
        if '%s' in line and 'execute' in line:
            # 检查是否使用了参数化查询
            if re.search(r'execute\s*\(\s*[^,]+,\s*\(', line):
                continue
        
        # 危险模式：字符串拼接
        if '+' in line or '%' in line:
            vulnerabilities.append({
                "vulnerability_type": "SQL注入",
                "confidence": 0.90,
                "affected_lines": [i],
                "root_cause": "使用字符串拼接构造 SQL 查询",
                "description": "攻击者可以通过注入恶意 SQL 语句来绕过认证或窃取数据",
                "cwe_id": "CWE-89"
            })
        # f-string 注入
        elif re.search(r'f["\'].*\{.*\}.*["\']', line):
            vulnerabilities.append({
                "vulnerability_type": "SQL注入",
                "confidence": 0.85,
                "affected_lines": [i],
                "root_cause": "使用 f-string 构造 SQL 查询",
                "description": "f-string 直接将变量插入 SQL，存在注入风险",
                "cwe_id": "CWE-89"
            })
        # .format() 注入
        elif '.format(' in line:
            vulnerabilities.append({
                "vulnerability_type": "SQL注入",
                "confidence": 0.85,
                "affected_lines": [i],
                "root_cause": "使用 .format() 构造 SQL 查询",
                "description": ".format() 直接将变量插入 SQL，存在注入风险",
                "cwe_id": "CWE-89"
            })
    
    return vulnerabilities

@router.post("/", response_model=List[AnalyzeResponse])
async def analyze_code(request: AnalyzeRequest):
    """
    分析代码中的安全漏洞
    
    - **code**: 要分析的源代码
    - **language**: 编程语言 (c/cpp/python/java)
    - **filename**: 可选的文件名

    策略：先用规则快速检测，如果没有发现漏洞，再调用阿里云 API 深度分析
    """
    request_id = f"req_{int(time.time())}_{hash(request.code[:100])}"
    
    # ========== 1. 空代码检查 ==========
    if not request.code or len(request.code.strip()) == 0:
        logger.info(f"[{request_id}] 输入为空")
        return [{
            "vulnerability_type": "输入为空",
            "confidence": 1.0,
            "affected_lines": [],
            "root_cause": "未提供待分析的代码",
            "description": "请输入需要分析的源代码后再进行分析。",
            "cwe_id": "CWE-200"
        }]
    
    # ========== 2. 超长代码检查 ==========
    if len(request.code) > MAX_CODE_LENGTH:
        logger.info(f"[{request_id}] 代码超长: {len(request.code)} 字符")
        return [{
            "vulnerability_type": "代码长度超限",
            "confidence": 1.0,
            "affected_lines": [],
            "root_cause": f"代码长度超过限制（最大{MAX_CODE_LENGTH}字符）",
            "description": f"当前代码长度为{len(request.code)}字符，请缩减代码长度后重试。",
            "cwe_id": "CWE-200"
        }]
    
    # ========== 语言检查（合并） ==========
    selected_lang = request.language.lower()
    actual_lang = detect_actual_language(request.code)
    
    # 1. 检查语言是否支持
    if selected_lang not in SUPPORTED_LANGUAGES:
        logger.info(f"[{request_id}] 不支持的语言: {selected_lang}")
        return [{
            "vulnerability_type": "不支持的语言",
            "confidence": 1.0,
            "affected_lines": [],
            "root_cause": f"当前不支持 {selected_lang} 语言",
            "description": f"系统目前支持的语言：{', '.join(SUPPORTED_LANGUAGES)}。",
            "cwe_id": "CWE-200"
        }]
    
    # 2. 检查语言是否匹配
    if actual_lang and actual_lang != selected_lang:
        logger.info(f"[{request_id}] 语言不匹配: 选择={selected_lang}, 实际={actual_lang}")
        return [{
            "vulnerability_type": "语言不匹配",
            "confidence": 1.0,
            "affected_lines": [],
            "root_cause": f"您选择的语言是 {selected_lang}，但代码看起来像是 {actual_lang}",
            "description": f"请将语言选择改为 {actual_lang}，或修改代码使其符合 {selected_lang} 语法。",
            "cwe_id": "CWE-200"
        }]
    # 3. 检查代码是否包含有效的语言特征（新增）
    if not actual_lang and len(request.code.strip()) > 0:
        # 代码非空但无法识别语言
        return [{
            "vulnerability_type": "无法识别代码语言",
            "confidence": 1.0,
            "affected_lines": [],
            "root_cause": "无法识别代码的编程语言",
            "description": f"系统无法识别您输入的代码。请确保输入的是 {', '.join(SUPPORTED_LANGUAGES)} 语言的代码，或选择正确的编程语言。",
            "cwe_id": "CWE-200"
        }]
    # ========== 4. 语法错误检查 ==========
    syntax_result = check_syntax_error(request.code, request.language)
    if syntax_result["has_error"]:
        logger.info(f"[{request_id}] 发现语法错误: {syntax_result['error_message']}")
        return [{
            "vulnerability_type": "语法错误",
            "confidence": 1.0,
            "affected_lines": [syntax_result["error_line"]] if syntax_result["error_line"] else [],
            "root_cause": syntax_result["error_message"],
            "description": f"代码存在语法错误，请修正后再进行分析。{syntax_result['error_message']}",
            "cwe_id": "CWE-200"
        }]
        # ========== 5. 规则快速检测（优先） ==========
    code_lines = request.code.split('\n')
    rule_vulnerabilities = []
    
    # 5.1 通用 CWE 规则检测
    for cwe_id, rule in CWE_RULES.items():
        patterns = rule.get("patterns", [])
        for pattern in patterns:
            for i, line in enumerate(code_lines, 1):
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        existing = [v for v in rule_vulnerabilities if v.get("cwe_id") == cwe_id and i in v.get("affected_lines", [])]
                        if not existing:
                            rule_vulnerabilities.append({
                                "vulnerability_type": rule["description"],
                                "confidence": 0.85,
                                "affected_lines": [i],
                                "root_cause": rule["message"],
                                "description": rule["message"] + "，建议使用安全的方式替代。",
                                "cwe_id": cwe_id
                            })
                except re.error:
                    continue
    
    # 5.2 特定规则检测（strcpy/gets/命令注入/SQL注入）
    # strcpy
    for i, line in enumerate(code_lines, 1):
        if "strcpy" in line:
            existing = [v for v in rule_vulnerabilities if v.get("cwe_id") == "CWE-120" and i in v.get("affected_lines", [])]
            if not existing:
                rule_vulnerabilities.append({
                    "vulnerability_type": "缓冲区溢出",
                    "confidence": 0.95,
                    "affected_lines": [i],
                    "root_cause": "使用了不安全的 strcpy 函数",
                    "description": "strcpy 不检查缓冲区大小，建议使用 strncpy",
                    "cwe_id": "CWE-120"
                })
    
    # gets
    for i, line in enumerate(code_lines, 1):
        if "gets" in line:
            existing = [v for v in rule_vulnerabilities if v.get("cwe_id") == "CWE-120" and i in v.get("affected_lines", [])]
            if not existing:
                rule_vulnerabilities.append({
                    "vulnerability_type": "缓冲区溢出",
                    "confidence": 0.98,
                    "affected_lines": [i],
                    "root_cause": "使用了不安全的 gets 函数",
                    "description": "gets 不检查输入长度，建议使用 fgets",
                    "cwe_id": "CWE-120"
                })
    
    # 命令注入
    for i, line in enumerate(code_lines, 1):
        if "system" in line and not is_safe_system_call(line):
            if "input" in line or "argv" in line or "+" in line:
                existing = [v for v in rule_vulnerabilities if v.get("cwe_id") == "CWE-78" and i in v.get("affected_lines", [])]
                if not existing:
                    rule_vulnerabilities.append({
                        "vulnerability_type": "命令注入",
                        "confidence": 0.85,
                        "affected_lines": [i],
                        "root_cause": "用户输入直接传递给 system 函数",
                        "description": "可能导致命令注入攻击",
                        "cwe_id": "CWE-78"
                    })
        
        if "subprocess.run" in line or "subprocess.Popen" in line:
            if "shell=True" in line:
                existing = [v for v in rule_vulnerabilities if v.get("cwe_id") == "CWE-78" and i in v.get("affected_lines", [])]
                if not existing:
                    rule_vulnerabilities.append({
                        "vulnerability_type": "命令注入",
                        "confidence": 0.90,
                        "affected_lines": [i],
                        "root_cause": "subprocess 使用了 shell=True，存在命令注入风险",
                        "description": "shell=True 会启用 shell 解析，用户输入可能被解释为额外命令",
                        "cwe_id": "CWE-78"
                    })
    
    # SQL 注入
    sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE"]
    for i, line in enumerate(code_lines, 1):
        if any(keyword in line.upper() for keyword in sql_keywords):
            if '%s' in line and 'execute' in line:
                if re.search(r'execute\s*\(\s*[^,]+,\s*\(', line):
                    continue
            
            if "+" in line or "%" in line:
                existing = [v for v in rule_vulnerabilities if v.get("cwe_id") == "CWE-89" and i in v.get("affected_lines", [])]
                if not existing:
                    rule_vulnerabilities.append({
                        "vulnerability_type": "SQL注入",
                        "confidence": 0.90,
                        "affected_lines": [i],
                        "root_cause": "使用字符串拼接构造 SQL 查询",
                        "description": "攻击者可以通过注入恶意 SQL 语句来绕过认证或窃取数据",
                        "cwe_id": "CWE-89"
                    })
            elif re.search(r'f["\'].*\{.*\}.*["\']', line):
                existing = [v for v in rule_vulnerabilities if v.get("cwe_id") == "CWE-89" and i in v.get("affected_lines", [])]
                if not existing:
                    rule_vulnerabilities.append({
                        "vulnerability_type": "SQL注入",
                        "confidence": 0.85,
                        "affected_lines": [i],
                        "root_cause": "使用 f-string 构造 SQL 查询",
                        "description": "f-string 直接将变量插入 SQL，存在注入风险",
                        "cwe_id": "CWE-89"
                    })
    
    # 5.3 Go 特有规则
    for i, line in enumerate(code_lines, 1):
        if "if err != nil" in line and "return err" in line:
            existing = [v for v in rule_vulnerabilities if v.get("cwe_id") == "CWE-754" and i in v.get("affected_lines", [])]
            if not existing:
                rule_vulnerabilities.append({
                    "vulnerability_type": "错误处理不当",
                    "confidence": 0.80,
                    "affected_lines": [i],
                    "root_cause": "错误处理不完整，可能掩盖问题",
                    "description": "Go 语言中错误处理应记录日志或向上传递",
                    "cwe_id": "CWE-754"
                })
        
        if "go func" in line and "close(ch)" in line:
            existing = [v for v in rule_vulnerabilities if v.get("cwe_id") == "CWE-362" and i in v.get("affected_lines", [])]
            if not existing:
                rule_vulnerabilities.append({
                    "vulnerability_type": "并发安全隐患",
                    "confidence": 0.75,
                    "affected_lines": [i],
                    "root_cause": "goroutine 可能向已关闭的 channel 发送数据",
                    "description": "需确保 channel 在所有写入完成后才关闭",
                    "cwe_id": "CWE-362"
                })
    
    # ========== 6. 如果规则检测发现漏洞，直接返回 ==========
    if rule_vulnerabilities:
        logger.info(f"[{request_id}] 规则检测发现 {len(rule_vulnerabilities)} 个漏洞，直接返回（不调用API）")
        return rule_vulnerabilities
    
    # ========== 7. 规则未发现漏洞，调用阿里云 API 深度分析 ==========
    logger.info(f"[{request_id}] 规则未发现漏洞，调用阿里云 API 深度分析")
    
        # ========== 5. 调用模型进行深度分析 ==========
  
    try:
        prompt = f"""你是一个代码安全专家。请分析以下{request.language}代码中的安全漏洞：

        ```{request.language}
        {request.code}

        判断标准：

         命令注入：只有使用 shell=True 或字符串拼接调用 system() 才算漏洞

         ✅ 危险：os.system("ping " + user_input)

         ✅ 危险：subprocess.run("ping " + user_input, shell=True)

         ❌ 安全：subprocess.run(["ping", user_input]) # 参数列表方式

         SQL注入：只有字符串拼接、f-string、.format() 才算漏洞

         ✅ 危险：query = "SELECT * FROM users WHERE name = '" + name + "'"

         ❌ 安全：query = "SELECT * FROM users WHERE name = %s"; cursor.execute(query, (name,))

         如果没有漏洞，返回空数组 []
        请按以下JSON格式输出分析结果，不要包含任何其他内容：

         [
         {{
         "vulnerability_type": "漏洞类型名称",
         "confidence": 0.95,
         "affected_lines": [1, 2, 3],
         "root_cause": "漏洞的根本原因",
         "description": "漏洞的详细描述",
         "cwe_id": "CWE-120"
         }}
         ]
         如果代码安全，只输出：[]

         注意：

        必须输出合法的JSON数组
        confidence必须在0-1之间
        affected_lines是整数数组
        cwe_id格式为"CWE-数字"
        """
        logger.info(f"[{request_id}] 开始分析代码，语言: {request.language}")
        start_time = time.time()

        logger.info(f"[{request_id}] 调用模型，prompt长度: {len(prompt)}")

        result = await model_service.generate_with_timeout(prompt)

        logger.info(f"[{request_id}] 模型返回success: {result.get('success')}")
        if result.get("output"):
            logger.info(f"[{request_id}] 模型返回内容前500字符: {result['output'][:500]}")
        else:
            logger.error(f"[{request_id}] 模型返回output为空")
        if not result["success"]:
            logger.error(f"[{request_id}] 模型调用失败: {result['error']}")
             # 返回"未发现漏洞"而不是空列表
            return [{
                "vulnerability_type": "未发现明显漏洞",
                "confidence": 0.99,
                "affected_lines": [],
                "root_cause": "代码未检测到常见安全漏洞模式",
                "description": "经过安全分析，当前代码未发现明显的安全漏洞。建议继续进行完整的安全审计。",
                "cwe_id": "CWE-200"  # 信息泄露（用于表示"无漏洞"的占位）
            }]
        
        try:
            analyses = json.loads(result["output"])
            if not isinstance(analyses, list):
                logger.warning(f"[{request_id}] 返回的不是列表，转换为列表")
                analyses = [analyses] if analyses else []
            logger.info(f"[{request_id}] 成功解析分析结果，发现 {len(analyses)} 个漏洞")
            validated_analyses = []
            for analysis in analyses:
                if validate_analysis_result(analysis):
                    validated_analyses.append(analysis)
                else:
                    logger.warning(f"[{request_id}] 跳过无效的分析结果: {analysis}")
            
                analysis_time = time.time() - start_time
                logger.info(f"[{request_id}] 分析完成，耗时: {analysis_time:.2f}秒")
            
   
            # 如果验证后没有漏洞，返回明确结果
            if not validated_analyses:
                return [{
                    "vulnerability_type": "未发现明显漏洞",
                    "confidence": 0.99,
                    "affected_lines": [],
                    "root_cause": "代码未检测到常见安全漏洞模式",
                    "description": "经过安全分析，当前代码未发现明显的安全漏洞。建议继续进行完整的安全审计。",
                    "cwe_id": "CWE-200"
                }]
            
            return validated_analyses
            
        except json.JSONDecodeError:
            logger.warning(f"[{request_id}] 直接解析JSON失败，尝试提取JSON数组")

            json_match = re.search(r'\[[\s\S]*\]', result["output"], re.DOTALL)
            if json_match:
                try:
                    analyses = json.loads(json_match.group())
                    if not isinstance(analyses, list):
                        analyses = [analyses]
                    
                    logger.info(f"[{request_id}] 通过提取成功解析，发现 {len(analyses)} 个漏洞")
                    
                    validated_analyses = []
                    for analysis in analyses:
                        if validate_analysis_result(analysis):
                            validated_analyses.append(analysis)
                        else:
                            logger.warning(f"[{request_id}] 跳过无效的分析结果: {analysis}")
                    
                    analysis_time = time.time() - start_time
                    logger.info(f"[{request_id}] 分析完成，耗时: {analysis_time:.2f}秒")
                    
                    
                    
               # 如果验证后没有漏洞，返回明确结果
                    if not validated_analyses:
                        return [{
                            "vulnerability_type": "未发现明显漏洞",
                            "confidence": 0.99,
                            "affected_lines": [],
                            "root_cause": "代码未检测到常见安全漏洞模式",
                            "description": "经过安全分析，当前代码未发现明显的安全漏洞。建议继续进行完整的安全审计。",
                            "cwe_id": "CWE-200"
                        }]
                    
                    return validated_analyses
                    
                except json.JSONDecodeError as e:
                    logger.error(f"[{request_id}] 提取的JSON解析失败: {e}")
                    return [{
                        "vulnerability_type": "未发现明显漏洞",
                        "confidence": 0.99,
                        "affected_lines": [],
                        "root_cause": "无法解析分析结果，代码可能安全",
                        "description": "模型返回格式异常，但未检测到明确的安全漏洞。建议手动审查代码。",
                        "cwe_id": "CWE-200"
                    }]
            else:
                logger.error(f"[{request_id}] 未找到JSON数组")
                return [{
                    "vulnerability_type": "未发现明显漏洞",
                    "confidence": 0.99,
                    "affected_lines": [],
                    "root_cause": "模型未返回有效的分析结果，代码可能安全",
                    "description": "无法获取有效的漏洞分析结果，建议手动审查代码。",
                    "cwe_id": "CWE-200"
                }]
                
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{request_id}] 分析失败: {str(e)}")
        # 出错时也返回"未发现漏洞"而不是空列表
        return [{
            "vulnerability_type": "分析失败",
            "confidence": 0.0,
            "affected_lines": [],
            "root_cause": f"分析过程中出现错误: {str(e)}",
            "description": "无法完成安全分析，请检查代码格式或稍后重试。",
            "cwe_id": "CWE-200"
        }]
@router.post("/mock")
async def analyze_mock(request: AnalyzeRequest):
    """
    模拟分析接口（用于前端开发和测试）
    基于简单的规则匹配返回模拟的漏洞分析结果
    """
    # ========== 1. 空代码检查 ==========
    if not request.code or len(request.code.strip()) == 0:
        return [{
            "vulnerability_type": "输入为空",
            "confidence": 1.0,
            "affected_lines": [],
            "root_cause": "未提供待分析的代码",
            "description": "请输入需要分析的源代码后再进行分析。",
            "cwe_id": "CWE-200"
        }]

    # ========== 2. 超长代码检查 ==========
    if len(request.code) > MAX_CODE_LENGTH:
        return [{
            "vulnerability_type": "代码长度超限",
            "confidence": 1.0,
            "affected_lines": [],
            "root_cause": f"代码长度超过限制（最大{MAX_CODE_LENGTH}字符）",
            "description": f"当前代码长度为{len(request.code)}字符，请缩减代码长度后重试。",
            "cwe_id": "CWE-200"
        }]

    # ========== 语言检查（合并） ==========
    selected_lang = request.language.lower()
    actual_lang = detect_actual_language(request.code)
    
    # 1. 检查语言是否支持
    if selected_lang not in SUPPORTED_LANGUAGES:
        return [{
            "vulnerability_type": "不支持的语言",
            "confidence": 1.0,
            "affected_lines": [],
            "root_cause": f"当前不支持 {selected_lang} 语言",
            "description": f"系统目前支持的语言：{', '.join(SUPPORTED_LANGUAGES)}。",
            "cwe_id": "CWE-200"
        }]
    
    # 2. 检查语言是否匹配
    if actual_lang and actual_lang != selected_lang:
        return [{
            "vulnerability_type": "语言不匹配",
            "confidence": 1.0,
            "affected_lines": [],
            "root_cause": f"您选择的语言是 {selected_lang}，但代码看起来像是 {actual_lang}",
            "description": f"请将语言选择改为 {actual_lang}，或修改代码使其符合 {selected_lang} 语法。",
            "cwe_id": "CWE-200"
        }]
    

    # ========== 4. 语法错误检查 ==========
    syntax_result = check_syntax_error(request.code, request.language)
    if syntax_result["has_error"]:
        return [{
            "vulnerability_type": "语法错误",
            "confidence": 1.0,
            "affected_lines": [syntax_result["error_line"]] if syntax_result["error_line"] else [],
            "root_cause": syntax_result["error_message"],
            "description": f"代码存在语法错误，请修正后再进行分析。{syntax_result['error_message']}",
            "cwe_id": "CWE-200"
        }]

    vulnerabilities = []
    code_lines = request.code.split('\n')

    # ========== 5. 通用 CWE 规则检测 ==========
    for cwe_id, rule in CWE_RULES.items():
        patterns = rule.get("patterns", [])
        for pattern in patterns:
            for i, line in enumerate(code_lines, 1):
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        # 避免重复添加相同漏洞
                        existing = [v for v in vulnerabilities if v.get("cwe_id") == cwe_id and i in v.get("affected_lines", [])]
                        if not existing:
                            vulnerabilities.append({
                                "vulnerability_type": rule["description"],
                                "confidence": 0.85,
                                "affected_lines": [i],
                                "root_cause": rule["message"],
                                "description": rule["message"] + "，建议使用安全的方式替代。",
                                "cwe_id": cwe_id
                            })
                except re.error:
                    # 正则表达式错误时跳过
                    continue

    # ========== 6. 特定规则检测（补充） ==========
    # 规则: 检查 strcpy
    for i, line in enumerate(code_lines, 1):
        if "strcpy" in line:
            existing = [v for v in vulnerabilities if v.get("cwe_id") == "CWE-120" and i in v.get("affected_lines", [])]
            if not existing:
                vulnerabilities.append({
                    "vulnerability_type": "缓冲区溢出",
                    "confidence": 0.95,
                    "affected_lines": [i],
                    "root_cause": "使用了不安全的 strcpy 函数",
                    "description": "strcpy 不检查缓冲区大小，建议使用 strncpy",
                    "cwe_id": "CWE-120"
                })

    # 规则: 检查 gets
    for i, line in enumerate(code_lines, 1):
        if "gets" in line:
            existing = [v for v in vulnerabilities if v.get("cwe_id") == "CWE-120" and i in v.get("affected_lines", [])]
            if not existing:
                vulnerabilities.append({
                    "vulnerability_type": "缓冲区溢出",
                    "confidence": 0.98,
                    "affected_lines": [i],
                    "root_cause": "使用了不安全的 gets 函数",
                    "description": "gets 不检查输入长度，建议使用 fgets",
                    "cwe_id": "CWE-120"
                })

    # 规则: 命令注入（system）
    for i, line in enumerate(code_lines, 1):
        if "system" in line and not is_safe_system_call(line):
            if "input" in line or "argv" in line or "+" in line:
                existing = [v for v in vulnerabilities if v.get("cwe_id") == "CWE-78" and i in v.get("affected_lines", [])]
                if not existing:
                    vulnerabilities.append({
                        "vulnerability_type": "命令注入",
                        "confidence": 0.85,
                        "affected_lines": [i],
                        "root_cause": "用户输入直接传递给 system 函数",
                        "description": "可能导致命令注入攻击",
                        "cwe_id": "CWE-78"
                    })

    # 规则: subprocess 命令注入
    for i, line in enumerate(code_lines, 1):
        if "subprocess.run" in line or "subprocess.Popen" in line:
            if "shell=True" in line:
                existing = [v for v in vulnerabilities if v.get("cwe_id") == "CWE-78" and i in v.get("affected_lines", [])]
                if not existing:
                    vulnerabilities.append({
                        "vulnerability_type": "命令注入",
                        "confidence": 0.90,
                        "affected_lines": [i],
                        "root_cause": "subprocess 使用了 shell=True，存在命令注入风险",
                        "description": "shell=True 会启用 shell 解析，用户输入可能被解释为额外命令",
                        "cwe_id": "CWE-78"
                    })

    # 规则: SQL 注入
    sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE"]
    for i, line in enumerate(code_lines, 1):
        if any(keyword in line.upper() for keyword in sql_keywords):
            # 参数化查询是安全的
            if '%s' in line and 'execute' in line:
                if re.search(r'execute\s*\(\s*[^,]+,\s*\(', line):
                    continue
            
            if "+" in line or "%" in line:
                existing = [v for v in vulnerabilities if v.get("cwe_id") == "CWE-89" and i in v.get("affected_lines", [])]
                if not existing:
                    vulnerabilities.append({
                        "vulnerability_type": "SQL注入",
                        "confidence": 0.90,
                        "affected_lines": [i],
                        "root_cause": "使用字符串拼接构造 SQL 查询",
                        "description": "攻击者可以通过注入恶意 SQL 语句来绕过认证或窃取数据",
                        "cwe_id": "CWE-89"
                    })
            elif re.search(r'f["\'].*\{.*\}.*["\']', line):
                existing = [v for v in vulnerabilities if v.get("cwe_id") == "CWE-89" and i in v.get("affected_lines", [])]
                if not existing:
                    vulnerabilities.append({
                        "vulnerability_type": "SQL注入",
                        "confidence": 0.85,
                        "affected_lines": [i],
                        "root_cause": "使用 f-string 构造 SQL 查询",
                        "description": "f-string 直接将变量插入 SQL，存在注入风险",
                        "cwe_id": "CWE-89"
                    })

    # ========== 7. 如果没有发现漏洞 ==========
    if not vulnerabilities:
        return [{
            "vulnerability_type": "未发现明显漏洞",
            "confidence": 0.99,
            "affected_lines": [],
            "root_cause": "代码未检测到常见安全漏洞模式",
            "description": "经过安全分析，当前代码未发现明显的安全漏洞。代码使用了安全的API调用方式。",
            "cwe_id": "CWE-200"
        }]

    return vulnerabilities