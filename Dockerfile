FROM python:3.11-slim

WORKDIR /app

# Copia requirements e installa dipendenze
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia tutto il backend
COPY backend/ ./backend/

# Esponi porta
EXPOSE 8000

# Avvia server
CMD ["sh", "-c", "cd backend && uvicorn server:app --host 0.0.0.0 --port $PORT"]
