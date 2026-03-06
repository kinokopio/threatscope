#!/bin/bash
set -e

chown -R appuser:appuser /app/data

if [ -S /var/run/docker.sock ]; then
    DOCKER_GID=$(stat -c '%g' /var/run/docker.sock)
    if ! getent group docker > /dev/null 2>&1; then
        groupadd -g "$DOCKER_GID" docker
    fi
    usermod -aG docker appuser
fi

exec gosu appuser "$@"
