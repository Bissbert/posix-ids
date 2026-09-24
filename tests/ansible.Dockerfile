# Image for the Ansible checks: ansible-core plus the collections the
# playbooks use, and the packages the roles install, preinstalled so the
# deploy test does not depend on the network.
FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends sudo cron logrotate procps net-tools \
      lsof netcat-openbsd gawk diffutils python3-apt dash \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /etc/security/limits.d
RUN pip install --no-cache-dir 'ansible-core>=2.17,<2.18' \
 && ansible-galaxy collection install 'ansible.posix:>=1.5,<2' 'community.general:>=9,<10'
