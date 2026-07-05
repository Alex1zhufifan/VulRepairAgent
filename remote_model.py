"""
远程模型服务 - 调用 AutoDL 上的漏洞修复 API
"""
import requests
import logging
import re
from typing import Dict, Any
import os

logger = logging.getLogger(__name__)

class RemoteModelService:
    """远程模型服务类，调用 AutoDL API"""
    
    def __init__(self):
        self.api_url = os.getenv("REMOTE_MODEL_URL")
        self.timeout = int(os.getenv("REMOTE_MODEL_TIMEOUT", "60"))
        logger.info(f"远程模型服务初始化，API地址: {self.api_url}")
    
    async def generate(self, prompt: str, timeout: int = None) -> Dict[str, Any]:
        """调用远程模型生成修复代码"""
        try:
            # 从 prompt 中提取代码
            code = self._extract_code_from_prompt(prompt)
            
            if not code:
                logger.error("提取的代码为空")
                return {
                    "success": False,
                    "error": "无法从提示词中提取代码"
                }
            
            # 准备请求数据
            data = {
                "code": code,
                "vuln_type": "通用漏洞"
            }
            
            logger.info(f"发送请求到远程API，代码长度: {len(code)}")
            
            # 发送请求
            response = requests.post(
                self.api_url,
                json=data,
                timeout=timeout or self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                result = response.json()
                fixed_code = result.get("fixed", "")
                
                return {
                    "success": True,
                    "output": fixed_code if fixed_code else "修复完成"
                }
            else:
                logger.error(f"远程API调用失败: {response.status_code}")
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text[:200]}"
                }
                
        except requests.exceptions.Timeout:
            logger.error(f"远程API调用超时")
            return {"success": False, "error": "请求超时"}
        except requests.exceptions.ConnectionError as e:
            logger.error(f"连接远程API失败: {str(e)}")
            return {"success": False, "error": f"连接失败: {str(e)}"}
        except Exception as e:
            logger.error(f"远程API调用出错: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _extract_code_from_prompt(self, prompt: str) -> str:
        """从提示词中提取原始代码"""
        # 确保 prompt 是字符串
        if not isinstance(prompt, str):
            prompt = str(prompt)
        
        # 尝试匹配代码块
        code_match = re.search(r'```(?:\w+)?\n(.*?)```', prompt, re.DOTALL)
        if code_match:
            extracted = code_match.group(1).strip()
            if extracted:
                return extracted
        
        # 如果没有代码块，尝试其他格式
        code_match = re.search(r'```(.*?)```', prompt, re.DOTALL)
        if code_match:
            extracted = code_match.group(1).strip()
            if extracted:
                return extracted
        
        # 如果都没有，返回原 prompt
        return prompt.strip()