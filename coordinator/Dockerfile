FROM rust:1.86 AS builder

WORKDIR /rustlib
COPY rustlib/ ./
RUN cargo install maturin
RUN maturin build --release --out /wheels


FROM python:3.11-slim

WORKDIR /app
COPY coordinator/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt


COPY --from=builder /wheels/*.whl /wheels/
RUN pip install /wheels/*.whl




COPY coordinator/ ./

CMD ["python", "coordinator.py"]