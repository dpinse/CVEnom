#!/bin/sh
# One image, several roles: api | worker | beat | migrate | create-admin | reset-mfa
set -eu

cmd="${1:-api}"
[ "$#" -gt 0 ] && shift

case "$cmd" in
  api)
    exec uvicorn cvenom.api.app:create_app --factory --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}" --ws-max-size 8192 --ws-max-queue 8 --ws-ping-interval 20 --limit-concurrency 500 --no-server-header
    ;;
  worker)
    exec celery -A cvenom.tasks:celery_app worker --loglevel=INFO --concurrency="${WORKER_CONCURRENCY:-2}"
    ;;
  beat)
    # Root fs is read-only; /tmp is tmpfs. Schedules are crontab-based and survive restarts.
    exec celery -A cvenom.tasks:celery_app beat --loglevel=INFO --schedule /tmp/celerybeat-schedule
    ;;
  migrate)
    cd /app
    exec alembic upgrade head
    ;;
  create-admin)
    exec python -m cvenom.cli create-admin "$@"
    ;;
  reset-mfa)
    # Break-glass: forget a user's MFA (lost device); revokes their sessions.
    exec python -m cvenom.cli reset-mfa "$@"
    ;;
  *)
    echo "usage: docker-entrypoint.sh api|worker|beat|migrate|create-admin|reset-mfa" >&2
    exit 64
    ;;
esac
