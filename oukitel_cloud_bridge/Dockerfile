ARG BUILD_FROM
FROM $BUILD_FROM

RUN pip3 install --no-cache-dir requests paho-mqtt pycryptodome

WORKDIR /app
COPY *.py /app/
COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
