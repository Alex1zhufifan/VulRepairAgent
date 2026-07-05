from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import (
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
    get_redoc_html
)
import logging

from app.api.v1.endpoints import analyze, generate, validate,auth,history
from app.core.config import settings

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 创建FastAPI应用（关闭所有默认文档）
app = FastAPI(
    title="VulRepairAgent API",
    description="漏洞代码修复代理系统",
    version="1.0.0",
    docs_url=None,  # 关闭默认docs
    redoc_url=None  # 关闭默认redoc
)

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(analyze.router, prefix="/api/v1/analyze", tags=["analyze"])
app.include_router(generate.router, prefix="/api/v1/generate", tags=["generate"])
app.include_router(validate.router, prefix="/api/v1/validate", tags=["validate"])
app.include_router(auth.router, prefix="/api/v1", tags=["auth"])
app.include_router(history.router, prefix="/api/v1", tags=["history"])

# 自定义 Swagger UI（使用国内镜像）
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="VulRepairAgent API - Swagger UI",
        swagger_js_url="https://cdn.bootcdn.net/ajax/libs/swagger-ui/5.0.0/swagger-ui-bundle.min.js",
        swagger_css_url="https://cdn.bootcdn.net/ajax/libs/swagger-ui/5.0.0/swagger-ui.min.css",
    )

# 自定义 ReDoc（使用国内镜像）
@app.get("/redoc", include_in_schema=False)
async def custom_redoc_html():
    return get_redoc_html(
        openapi_url="/openapi.json",
        title="VulRepairAgent API - ReDoc",
        redoc_js_url="https://cdn.bootcdn.net/ajax/libs/redoc/2.0.0/redoc.standalone.min.js",
    )

@app.get("/")
async def root():
    return {
        "message": "VulRepairAgent API is running",
        "version": "1.0.0",
        "docs": "/docs",
        "redoc": "/redoc"
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "device": settings.DEVICE,
        "model": settings.MODEL_NAME
    }

@app.on_event("startup")
async def startup_event():
    logger.info("Starting VulRepairAgent API...")
    logger.info(f"Device: {settings.DEVICE}")
    logger.info(f"Model: {settings.MODEL_NAME}")