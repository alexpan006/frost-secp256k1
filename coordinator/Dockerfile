FROM ghcr.io/pyo3/maturin as builder

WORKDIR /rustlib
COPY rustlib/ ./
RUN maturin build --release --out /wheels


FROM python:3.9-slim
WORKDIR /app
COPY coordinator/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt


COPY --from=builder /wheels/*.whl /wheels/
RUN pip install /wheels/*.whl




COPY coordinator/ ./

CMD ["python", "coordinator.py"]