#!/bin/sh
set -e

APP_UID="${LOGCOPILOT_UID:-10001}"
APP_GID="${LOGCOPILOT_GID:-10001}"

if [ "$(id -u)" = "0" ]; then
    if [ "$APP_GID" != "$(id -g appuser)" ]; then
        groupmod -o -g "$APP_GID" appuser
    fi
    if [ "$APP_UID" != "$(id -u appuser)" ]; then
        usermod -o -u "$APP_UID" -g "$APP_GID" appuser
    fi

    mkdir -p /app/out /app/.cache
    chown -R appuser:appuser /app/out /app/.cache

    exec gosu appuser logcopilot "$@"
fi

exec logcopilot "$@"
