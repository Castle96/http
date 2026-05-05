#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${1:-}"
PORT="${2:-443}"

if [[ -z "$DOMAIN" ]]; then
  echo "Usage: $0 <domain> [port]"
  exit 1
fi

RAW_CERT=$(echo | openssl s_client -connect "${DOMAIN}:${PORT}" -servername "${DOMAIN}" 2>/dev/null | openssl x509 -noout -text) || {
  echo "ERROR: Failed to fetch certificate from ${DOMAIN}:${PORT}"
  exit 2
}

ENDDATE=$(echo "$RAW_CERT" | openssl x509 -noout -enddate | cut -d= -f2)
SUBJECT=$(echo "$RAW_CERT" | openssl x509 -noout -subject | sed 's/subject= //')
ISSUER=$(echo "$RAW_CERT" | openssl x509 -noout -issuer | sed 's/issuer= //')

echo "Subject: $SUBJECT"
echo "Issuer:  $ISSUER"
echo "NotAfter: $ENDDATE"

if date --version >/dev/null 2>&1; then
  END_TS=$(date -d "$ENDDATE" +%s)
else
  END_TS=$(date -j -f "%b %e %T %Y %Z" "$ENDDATE" +%s 2>/dev/null || date -j -f "%b %e %T %Y %Z" "$ENDDATE" +%s)
fi

NOW_TS=$(date +%s)
DAYS_LEFT=$(( (END_TS - NOW_TS) / 86400 ))

echo "Days until expiry: $DAYS_LEFT"

ALERT_SUBJECT="[CERT ALERT] ${DOMAIN} certificate expires in ${DAYS_LEFT} days"
ALERT_BODY="Certificate check for ${DOMAIN}:${PORT}
Subject: ${SUBJECT}
Issuer: ${ISSUER}
NotAfter: ${ENDDATE}
Days left: ${DAYS_LEFT}
Checked at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"

notify_slack() {
  local webhook="$1"
  local text="$2"
  if command -v jq >/dev/null 2>&1; then
    curl -s -S -X POST -H 'Content-type: application/json' --data "{\"text\": $(jq -R -s <<< \"$text\") }" "$webhook" >/dev/null 2>&1 || {
      echo "Warning: failed to post to Slack webhook"
    }
  else
    curl -s -S -X POST -H 'Content-type: application/json' --data "$(printf '{"text":"%s"}' "$text")" "$webhook" >/dev/null 2>&1 || echo "Warning: failed to post fallback Slack payload"
  fi
}

notify_email() {
  local email="$1"
  local subject="$2"
  local body="$3"

  if command -v mailx >/dev/null 2>&1; then
    printf "%s\n" "$body" | mailx -s "$subject" "$email" || echo "Warning: mailx failed to send email to $email"
  elif command -v sendmail >/dev/null 2>&1; then
    {
      echo "Subject: $subject"
      echo "To: $email"
      echo
      echo "$body"
    } | sendmail -t || echo "Warning: sendmail failed to send email to $email"
  else
    echo "Warning: no mailx/sendmail available to send email to $email"
  fi
}

if [[ "$DAYS_LEFT" -le 30 ]]; then
  echo "ALERT: Certificate expires in $DAYS_LEFT days"

  if [[ -n "${SLACK_WEBHOOK:-}" ]]; then
    notify_slack "${SLACK_WEBHOOK}" "$ALERT_BODY"
  fi

  if [[ -n "${ALERT_EMAIL:-}" ]]; then
    notify_email "${ALERT_EMAIL}" "$ALERT_SUBJECT" "$ALERT_BODY"
  fi

  echo "$ALERT_BODY"
  exit 3
fi

echo "Certificate OK (>$DAYS_LEFT days left)"
exit 0