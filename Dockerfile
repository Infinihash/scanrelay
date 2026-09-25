FROM python:3.12-slim
RUN useradd -r -u 10001 scanrelay && mkdir -p /var/lib/scanrelay /var/log/scanrelay \
    && chown scanrelay /var/lib/scanrelay /var/log/scanrelay
WORKDIR /app
COPY pyproject.toml README.md ./
COPY scanrelay ./scanrelay
RUN pip install --no-cache-dir .
USER scanrelay
ENV SCANRELAY_SPOOL=/var/lib/scanrelay/spool SCANRELAY_LOG=/var/lib/scanrelay/sends.jsonl SCANRELAY_PORT=2525
EXPOSE 2525
VOLUME ["/var/lib/scanrelay"]
CMD ["scanrelay"]
