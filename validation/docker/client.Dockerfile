FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates python3 iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY validation/workloads/python_client/client.py /usr/local/bin/syntriass-python-client
RUN chmod +x /usr/local/bin/syntriass-python-client

ENTRYPOINT ["/usr/local/bin/syntriass-python-client"]
