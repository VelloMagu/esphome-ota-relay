ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache python3 py3-virtualenv \
    && python3 -m virtualenv /opt/relay \
    && /opt/relay/bin/pip install --no-cache-dir 'esphome==2026.11.0'

COPY relay.py /relay.py
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD ["/run.sh"]
