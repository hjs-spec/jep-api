FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 1000 jep
COPY --chown=jep:jep main.py state.py keys.py compatibility.py manage.py jep-event.schema.json ./
COPY --chown=jep:jep scripts/entrypoint.py ./entrypoint.py
ARG JEP_REVISION=unknown
ENV JEP_REVISION=$JEP_REVISION JEP_STATE_DIR=/data/jep PYTHONUNBUFFERED=1
RUN mkdir -p /data/jep && chown -R jep:jep /data
USER jep
EXPOSE 7860
HEALTHCHECK --interval=30s --timeout=15s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7860/health', timeout=12)"
ENTRYPOINT ["python", "entrypoint.py"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]
