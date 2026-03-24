ARG BUILD_FROM
FROM $BUILD_FROM

RUN apk add --no-cache python3 py3-pip && \
    pip3 install --no-cache-dir requests paho-mqtt pycryptodome

COPY *.py /app/
COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
