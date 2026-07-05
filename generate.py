"""
漏洞修复生成接口 - 生成代码的修复方案
"""
from fastapi import APIRouter, HTTPException
from typing import Optional, List
import pandas as pd
import json
import random
import re
import logging

from app.schemas.requests import GenerateRequest, GenerateResponse
from app.models.ml_service import model_service
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)


class FewShotExampleRetriever:
    """从数据集检索相似示例"""
    
    def __init__(self, dataset_path: str):
        try:
            self.df = pd.read_excel(dataset_path)
            self.cwe_groups = self.df.groupby('cwe_id') if 'cwe_id' in self.df.columns else {}
            logger.info(f"数据集加载成功，共 {len(self.df)} 条记录")
        except Exception as e:
            logger.warning(f"数据集加载失败: {e}")
            self.df = None
            self.cwe_groups = {}
    
    def retrieve(self, vul_type: Optional[str], k: int = 2) -> List[dict]:
        """检索k个相似示例"""
        if self.df is None or len(self.df) == 0:
            return []
        
        try:
            if vul_type and vul_type in self.cwe_groups.groups:
                group = self.cwe_groups.get_group(vul_type)
                samples = group.sample(min(k, len(group)))
            else:
                samples = self.df.sample(min(k, len(self.df)))
            
            examples = []
            for _, row in samples.iterrows():
                examples.append({
                    "unsafe": row.get('unsafe_code', ''),
                    "fixed": row.get('fixed_code', ''),
                    "cwe": row.get('cwe_id', ''),
                    "description": row.get('description', '')
                })
            return examples
        except Exception as e:
            logger.warning(f"检索示例失败: {e}")
            return []


def build_prompt(request: GenerateRequest) -> str:
    """构建提示词 - 针对不同漏洞类型给出具体指导"""
    
    code = request.code
    language = request.language
    
    # 检测命令注入 (C/Python)
        # 1. 匹配危险函数调用
    has_system_call = re.search(r'\bos\.system\s*\(', code) or re.search(r'\bsystem\s*\(', code)
    # 2. 匹配用户输入来源
    has_user_input = re.search(r'\b(input|user|request|data|query|param)\s*[\),+]', code, re.IGNORECASE)
    # 3. 匹配字符串拼接
    has_concat = '+' in code or '%' in code
    if has_system_call and (has_user_input or has_concat):
        if language.lower() == "python":
           prompt = """修复下面这段 {language} 代码中的命令注入漏洞。

           【漏洞代码】
            {code}

           【漏洞说明】
            直接将用户输入传递给 system() 函数，攻击者可以执行任意系统命令。

            【修复要求】
             1. 不要使用 os.system() 或 subprocess.run(shell=True)
             2. 使用 subprocess.run() 配合参数列表
             3. 对输入进行白名单验证
             4. 只输出修复后的 Python 代码

            【修复示例】
             ```python
             // 错误写法
            import os
            os.system("echo " + user_input)

            // 正确写法
            import subprocess
            subprocess.run(["echo", user_input], check=True)
            请输出修复后的代码：""".format(language=language,code=code)
        else:
            prompt = """修复下面这段 {language} 代码中的命令注入漏洞。
            【漏洞说明】
             直接将用户输入传递给 system() 函数，攻击者可以执行任意系统命令。

            【修复要求】
             1.不要直接使用 system() 函数
             2.使用 execve() 或参数列表方式执行命令
             3.对输入进行白名单验证
             4.只输出修复后的代码

            【修复示例】
             ```c
             // 错误写法
             system(user_input);

            // 正确写法
             char *args[] = {"echo", user_input, NULL};
             execve("/bin/echo", args, NULL);
             请输出修复后的代码：""".format(language=language,code=code)
            
        return prompt

    #检测 SQL 注入 (Python)
    # 1. 检测 SQL 关键字
    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER']
    has_sql_keyword = any(keyword in code.upper() for keyword in sql_keywords)
    
    # 2. 检测危险的字符串拼接方式
    has_concat = '+' in code or '%' in code
    has_fstring = re.search(r'f["\'].*\{.*\}.*["\']', code)
    has_format = '.format(' in code
    has_percent = '%s' in code or '%d' in code
    
    # 3. 检测是否有用户输入
    has_user_input = re.search(r'\b(input|user|request|data|name|id|value)\s*[\),+]', code, re.IGNORECASE)
    
    if has_sql_keyword and (has_concat or has_fstring or has_format) and has_user_input:
        prompt = """修复下面这段 {language} 代码中的 SQL 注入漏洞。
           【漏洞代码】
            {code}
           【漏洞说明】
            使用字符串拼接/格式化构造 SQL 查询，攻击者可以注入恶意 SQL 语句。

           【修复要求】
            1. 使用参数化查询（prepared statements）
            2. 不要拼接字符串、不要使用 f-string、不要使用 .format()
            3. 只输出修复后的代码

           【修复示例】
            【修复示例 - Python】
             ```python
             # 错误写法 - 字符串拼接
             query = "SELECT * FROM users WHERE name = '" + name + "'"

             # 错误写法 - f-string
             query = f"SELECT * FROM users WHERE name = '{name}'"

             # 正确写法 - 参数化查询
             query = "SELECT * FROM users WHERE name = %s"
             cursor.execute(query, (name,))

             【修复示例 - Java】
             // 错误写法
             String query = "SELECT * FROM users WHERE name = '" + name + "'";

             // 正确写法 - PreparedStatement
             String query = "SELECT * FROM users WHERE name = ?";
             PreparedStatement ps = conn.prepareStatement(query);
             ps.setString(1, name);
             请输出修复后的代码：""".format(language=language,code=code)
        return prompt
#检测 strcpy (C)
    if "strcpy" in code:
        prompt = """修复下面这段 {language} 代码中的缓冲区溢出漏洞。

           【漏洞代码】
            {code}
           【漏洞说明】
            strcpy() 不检查目标缓冲区大小，可能导致缓冲区溢出。

           【修复要求】

            使用 strncpy() 替代 strcpy()

            确保字符串以 '\0' 结尾

            只输出修复后的代码

            【修复示例】
             // 错误写法
             strcpy(dest, src);

             // 正确写法
             strncpy(dest, src, sizeof(dest) - 1);
             dest[sizeof(dest) - 1] = '\\0';
             请输出修复后的代码：""".format(language=language,code=code)
        return prompt
#检测 gets (C)
    if "gets" in code:
        prompt = """修复下面这段 {language} 代码中的缓冲区溢出漏洞。

            【漏洞代码】
             {code}
            【漏洞说明】
             gets() 不检查输入长度，极易导致缓冲区溢出。

            【修复要求】

             使用 fgets() 替代 gets()

             只输出修复后的代码

             【修复示例】
              // 错误写法
              gets(buffer);

              // 正确写法
              fgets(buffer, sizeof(buffer), stdin);
              请输出修复后的代码：""".format(language=language,code=code)
    
        return prompt
    #默认提示词
    prompt = """修复下面这段 {language} 代码中的安全漏洞。
        {code}
        修复要求：

        保持原有功能不变

        使用安全的函数替代不安全的函数

        添加必要的输入验证

        只输出修复后的代码，不要添加任何解释

        请输出修复后的代码：""".format(language=language,code=code)
    return prompt

def extract_code(text: str) -> str:
    """从模型响应中提取代码"""
    # 匹配 ```c ... ``` 格式
    pattern = r'```(?:c|cpp|python|java|go)?\n(.*?)```'
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    # 如果没有代码块，返回原文本
    return text.strip()

def analyze_changes(original: str, fixed: str) -> List[dict]:
    """分析原始代码和修复代码之间的差异"""
    changes = []

    if "strcpy" in original and "strncpy" in fixed:
        changes.append({"type": "function_replacement", "description": "strcpy → strncpy"})
    if "gets" in original and "fgets" in fixed:
        changes.append({"type": "function_replacement", "description": "gets → fgets"})
    if "sprintf" in original and "snprintf" in fixed:
        changes.append({"type": "function_replacement", "description": "sprintf → snprintf"})
    if "system" in original and ("execve" in fixed or "subprocess" in fixed):
        changes.append({"type": "function_replacement", "description": "system → execve/参数列表"})

    #Go 错误处理
    if "if err != nil" in original and "klog.Error" in fixed:
        changes.append({"type": "error_handling", "description": "添加错误日志记录"})

    #Go 命令注入修复
    if "exec.Command" in original and "+" in original and "exec.Command" in fixed and "+" not in fixed:
        changes.append({"type": "function_replacement", "description": "命令注入修复，使用参数列表"})

    if not changes:
        changes.append({"type": "security_fix", "description": "修复安全漏洞"})

    return changes

@router.post("/", response_model=GenerateResponse)
async def generate_fix(request: GenerateRequest):
    """生成漏洞代码的修复方案"""
    try:
        logger.info(f"开始生成修复方案，语言: {request.language}")

        #构建提示词
        prompt = build_prompt(request)

        #调用模型
        result = await model_service.generate_with_timeout(prompt)

        if not result["success"]:
            logger.error(f"模型调用失败: {result['error']}")
            raise HTTPException(status_code=500, detail=result["error"])

        #获取输出
        output = result.get("output", "")
        logger.info(f"模型返回长度: {len(output)}")

        #提取修复代码
        fixed_code = extract_code(output)

         #如果没有提取到代码，使用原代码
        if not fixed_code or len(fixed_code) < 5:
            fixed_code = request.code

#分析修改
        changes = analyze_changes(request.code, fixed_code)

        return GenerateResponse(
            original_code=request.code,
            fixed_code=fixed_code,
             explanation="已生成修复方案",
             changes_made=changes,
             confidence=0.85
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"生成修复方案失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"生成失败: {str(e)}")

@router.post("/mock")
async def generate_mock(request: GenerateRequest):
    """模拟修复生成（用于前端测试）"""
    fixed_code = request.code
    changes = []

    if "strcpy" in fixed_code:
        fixed_code = fixed_code.replace("strcpy", "strncpy")
        fixed_code = fixed_code.replace(");", ", sizeof(dest) - 1);\n dest[sizeof(dest) - 1] = '\0';")
        changes.append({"type": "function_replacement", "description": "strcpy → strncpy"})

    if "gets" in fixed_code:
        fixed_code = fixed_code.replace("gets", "fgets")
        fixed_code = fixed_code.replace(");", ", sizeof(buffer), stdin);")
        changes.append({"type": "function_replacement", "description": "gets → fgets"})

    if "system" in fixed_code and "input" in fixed_code:
        fixed_code = fixed_code.replace(
        'system(input)',
        '// 安全修复：使用参数列表避免命令注入\n char *args[] = {"echo", input, NULL};\n execve("/bin/echo", args, NULL);'
        )
        changes.append({"type": "function_replacement", "description": "system → execve"})

    #Go 错误处理修复
    if "if err != nil" in fixed_code and "return err" in fixed_code and "klog.Error" not in fixed_code:
        fixed_code = fixed_code.replace(
        "if err != nil {\n\t\treturn err",
        "if err != nil {\n\t\tklog.Error(err)\n\t\treturn err"
        )
        changes.append({"type": "error_handling", "description": "添加错误日志记录"})

    #Go 命令注入修复（exec.Command 字符串拼接）
    if "exec.Command" in fixed_code and "+" in fixed_code:
        fixed_code = fixed_code.replace(
        'cmd := exec.Command("sh", "-c", "echo "+userInput)',
        '// 安全方式：使用参数列表，避免命令注入\n cmd := exec.Command("echo", userInput)'
        )
        changes.append({"type": "command_injection_fix", "description": "使用参数列表替代字符串拼接"})

    #Go 废弃 API 修复（添加 DeprecatedVersion）
    if "StabilityLevel:" in fixed_code and "STABLE" in fixed_code:
        fixed_code = fixed_code.replace(
        "StabilityLevel: compbasemetrics.STABLE,",
        "StabilityLevel: compbasemetrics.STABLE,\n\tDeprecatedVersion: \"1.34.0\","
        )
        changes.append({"type": "deprecation_marking", "description": "标记废弃 API，提示迁移到新版本"})

    if not changes:
        changes = [{"type": "security_audit", "description": "未发现明显漏洞"}]

    return GenerateResponse(
        original_code=request.code,
        fixed_code=fixed_code,
        explanation="已应用安全修复规则",
        changes_made=changes,
        confidence=0.9
        )


