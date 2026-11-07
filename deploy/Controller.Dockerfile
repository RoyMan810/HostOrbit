ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONNOUSERSITE=1
WORKDIR /app
COPY wheelhouse /opt/wheelhouse
COPY requirements-install.txt /opt/requirements-install.txt
RUN --network=none python -m pip install --no-index --find-links=/opt/wheelhouse --require-hashes -r /opt/requirements-install.txt \
    && python -c "import sys,sqlite3; assert sys.version_info[:2] == (3,13); assert sqlite3.sqlite_version_info >= (3,45)" \
    && rm -rf /opt/wheelhouse /opt/requirements-install.txt
USER 65534:65534
ENTRYPOINT ["hostorbit-runtime", "--config", "/etc/hostorbit/runtime.json"]
