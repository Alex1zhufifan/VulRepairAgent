"""
模型服务层 - 支持阿里云百炼API、远程模型和Mock模式
"""
import asyncio
import logging
import os
import json
from typing import Dict, Any

logger = logging.getLogger(__name__)


class AliyunModelService:
    """阿里云百炼大模型 API 服务"""

    def __init__(self):
        self.api_key = os.getenv("ALIYUN_API_KEY")
        self.base_url = os.getenv("ALIYUN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
        self.model = os.getenv("ALIYUN_MODEL", "qwen-plus")
        self.timeout = int(os.getenv("REMOTE_MODEL_TIMEOUT", "60"))
        self.session = None
        logger.info(f"阿里云API初始化完成，模型: {self.model}")

    async def _get_session(self):
        if self.session is None or self.session.closed:
            import aiohttp
            self.session = aiohttp.ClientSession()
        return self.session

    async def generate(self, prompt: str, timeout: int = None) -> Dict[str, Any]:
        """调用阿里云百炼 API"""
        try:
            import aiohttp
            session = await self._get_session()

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            data = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "你是一个代码安全专家。你的任务是修复代码中的安全漏洞。你必须只返回修复后的代码，不要包含任何解释、问候语或其他文字。输出格式：直接输出代码，用```语言```包裹。"},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.1,
                "max_tokens": 1024
            }

            url = f"{self.base_url}/chat/completions"

            async with session.post(
                url,
                json=data,
                headers=headers,
                timeout=timeout or self.timeout
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    output = result["choices"][0]["message"]["content"]
                    logger.info(f"阿里云API调用成功，返回长度: {len(output)}")
                    return {"success": True, "output": output}
                else:
                    error_text = await response.text()
                    logger.error(f"阿里云API调用失败: {response.status} - {error_text}")
                    return {"success": False, "error": f"HTTP {response.status}"}

        except asyncio.TimeoutError:
            logger.error("阿里云API调用超时")
            return {"success": False, "error": "请求超时"}
        except Exception as e:
            logger.error(f"阿里云API调用出错: {str(e)}")
            return {"success": False, "error": str(e)}

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()


class RemoteModelService:
    """通用远程模型服务 - 调用自定义API"""

    def __init__(self):
        self.api_url = os.getenv("REMOTE_MODEL_URL")
        self.api_key = os.getenv("API_KEY")
        self.timeout = int(os.getenv("REMOTE_MODEL_TIMEOUT", "60"))
        self.session = None
        logger.info(f"远程模型API初始化完成，地址: {self.api_url}")

    async def _get_session(self):
        if self.session is None or self.session.closed:
            import aiohttp
            self.session = aiohttp.ClientSession()
        return self.session

    async def generate(self, prompt: str, timeout: int = None) -> Dict[str, Any]:
        """调用远程API"""
        try:
            import aiohttp
            session = await self._get_session()

            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            data = {
                "prompt": prompt, 
                "max_tokens": 1024,
                "temperature": 0.1
            }

            async with session.post(
                self.api_url,
                json=data,
                headers=headers,
                timeout=timeout or self.timeout
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    output = result.get("text") or result.get("output") or str(result)
                    return {"success": True, "output": output}
                else:
                    error_text = await response.text()
                    logger.error(f"远程API调用失败: {response.status} - {error_text}")
                    return {"success": False, "error": f"HTTP {response.status}"}

        except asyncio.TimeoutError:
            logger.error("远程API调用超时")
            return {"success": False, "error": "请求超时"}
        except Exception as e:
            logger.error(f"远程API调用出错: {str(e)}")
            return {"success": False, "error": str(e)}

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()


class MockModelService:
    """Mock 模式 - 返回模拟结果，用于测试"""

    async def generate(self, prompt: str, timeout: int = None) -> Dict[str, Any]:
        """返回模拟结果"""
        logger.info("使用 Mock 模式返回模拟结果")

        # 判断请求类型
        is_analysis = "分析以下" in prompt
        is_generate = "修复以下" in prompt or "修复后的代码" in prompt

        # 生成请求 - 返回修复后的代码
        if is_generate:
            if "strcpy" in prompt:
                fixed_code = '''void safe_function(char *input) {
    char buffer[10];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
}'''
            elif "gets" in prompt:
                fixed_code = '''void safe_function() {
    char buffer[10];
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\\n")] = '\\0';
}'''
            elif "system" in prompt:
                fixed_code = '''void safe_function(char *input) {
    if (is_valid_input(input)) {
        execve("/bin/echo", args, NULL);
    }
}'''
            elif "SELECT" in prompt and "+" in prompt:
                fixed_code = '''def get_user(username):
    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    return cursor.fetchall()'''
            else:
                fixed_code = "// 未检测到明显漏洞，无需修复"
            
            logger.info(f"返回修复代码，长度: {len(fixed_code)}")
            return {"success": True, "output": fixed_code}

        # 分析请求 - 返回漏洞分析结果
        if is_analysis:
            analysis = [{
                "vulnerability_type": "缓冲区溢出",
                "confidence": 0.95,
                "affected_lines": [2],
                "root_cause": "使用了不安全的 strcpy 函数",
                "description": "strcpy 不检查缓冲区大小，建议使用 strncpy",
                "cwe_id": "CWE-120"
            }]
            output = json.dumps(analysis, ensure_ascii=False)
            logger.info(f"返回分析结果，长度: {len(output)}")
            return {"success": True, "output": output}

        # 默认返回
        return {"success": True, "output": "未识别的请求类型"}


class ModelService:
    """模型服务主类 - 自动选择可用服务"""

    _instance = None
    _service = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)

            # 优先级1：阿里云百炼 API
            if os.getenv("ALIYUN_API_KEY"):
                logger.info("✓ 使用阿里云百炼大模型 API")
                cls._service = AliyunModelService()

            # 优先级2：自定义远程模型 API
            elif os.getenv("USE_REMOTE_MODEL", "false").lower() == "true" and os.getenv("REMOTE_MODEL_URL"):
                logger.info("✓ 使用自定义远程模型 API")
                cls._service = RemoteModelService()

            # 优先级3：Mock 模式
            else:
                logger.info("✓ 使用 Mock 模式（模拟结果）")
                cls._service = MockModelService()

        return cls._instance

    async def generate_with_timeout(self, prompt: str, timeout: int = None) -> Dict[str, Any]:
        """带超时控制的生成"""
        if self._service:
            return await self._service.generate(prompt, timeout)
        else:
            return {"success": False, "error": "未配置任何模型服务"}

    async def close(self):
        if self._service and hasattr(self._service, 'close'):
            await self._service.close()


# 创建全局实例
model_service = ModelService()