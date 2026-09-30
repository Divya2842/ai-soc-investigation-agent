# ==========================================
# Stage 1 - Build React Frontend
# ==========================================
FROM node:20-slim AS frontend-build

WORKDIR /frontend

COPY frontend/package.json ./
RUN npm install

COPY frontend/ ./

RUN npm run build


# ==========================================
# Stage 2 - FastAPI Backend
# ==========================================
FROM python:3.12-slim

WORKDIR /app

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY data/ ./data/

# Copy React build into the final container
COPY --from=frontend-build /frontend/dist ./frontend/dist

WORKDIR /app/backend

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["sh", "-c", "python -m app.database.seed && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]