#!/bin/bash
FILEBEAT="${FILEBEAT:-yes}"
AGGREGATED_STATS_LOG_FILE="${AGGREGATED_LOG_FILE:-/dev/stdout}"
ACCESS_LOG="${ACCESS_LOG:-/dev/stdout}"
ERROR_LOG="${ERROR_LOG:-/logs/error.log}"
# shellcheck disable=SC2016
envsubst '${TARGET_ADDRESS_A},${TARGET_PORT_A},${TARGET_ADDRESS_B},${TARGET_PORT_B},${AGGREGATED_STATS_LOGFILE},${ACCESS_LOG},${ERROR_LOG}' < /etc/nginx/conf.d/default.template > /etc/nginx/conf.d/default.conf
if [ "$FILEBEAT" = "yes" ]
then
  /usr/local/openresty/bin/openresty -g "daemon off;" | grep -v '^.$' | /usr/bin/filebeat --path.config /etc
else
  /usr/local/openresty/bin/openresty -g "daemon off;"
fi