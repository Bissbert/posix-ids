# Image for the shell regression tests: Debian's dash as /bin/sh, mawk,
# and the tools monitor.sh and setup.sh call.
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends procps net-tools cron bsdutils \
 && rm -rf /var/lib/apt/lists/*
