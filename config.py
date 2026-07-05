from pydantic_settings import BaseSettings
from functools import lru_cache
import torch
from typing import Optional

class Settings(BaseSettings):
    # 应用配置
    APP_NAME: str = "VulRepairAgent"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"
    
    # 模型配置
    MODEL_NAME: str = "codellama/CodeLlama-7b-hf"
    MODEL_CACHE_DIR: str = "./models"
    MODEL_LOAD_8BIT: bool = False
    MODEL_MAX_LENGTH: int = 2048
    MODEL_TIMEOUT: int = 30
    
    # 硬件配置
    DEVICE: str = "cuda" if torch.cuda.is_available() else "cpu"
    
    # 数据配置
    DATASET_PATH: str = "../data/VulRepair-1K.xlsx"
    
    # 安全配置
    DOCKER_TIMEOUT: int = 10
    MAX_CODE_SIZE: int = 10000
    
    class Config:
        env_file = ".env"
        extra = "ignore"

    # 远程模型配置（新增）
    USE_REMOTE_MODEL: bool = False
    REMOTE_MODEL_URL: Optional[str] = None
    REMOTE_MODEL_TIMEOUT: int = 60

@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()