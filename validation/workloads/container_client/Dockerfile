FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY validation/workloads/python_client/client.py /usr/local/bin/syntriass-container-client
RUN chmod +x /usr/local/bin/syntriass-container-client

ENTRYPOINT ["/usr/local/bin/syntriass-container-client"]
