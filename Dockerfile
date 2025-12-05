# 使用官方 Python 镜像作为基础镜像
FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 安装 uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# 复制项目文件
COPY . .

# 安装系统依赖 (Playwright 需要)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# 同步依赖并安装 playwright 浏览器
RUN uv sync --frozen
RUN uv run playwright install --with-deps chromium

# 设置入口点
ENTRYPOINT ["uv", "run"]
