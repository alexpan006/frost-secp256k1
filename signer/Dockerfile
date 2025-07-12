FROM ghcr.io/pyo3/maturin as builder

WORKDIR /rustlib
COPY rustlib/ ./
RUN maturin build --release --out /wheels

FROM python:3.9-slim

WORKDIR /app
COPY signer/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --from=builder /wheels/*.whl /wheels/
RUN pip install /wheels/*.whl

COPY signer/ ./

EXPOSE 8000

CMD ["uvicorn", "signer:app", "--host", "0.0.0.0", "--port", "8000"]