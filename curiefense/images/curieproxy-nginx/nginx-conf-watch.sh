#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
  set -o xtrace
fi

echo "Blindly calling reload script at start"
/usr/local/bin/nginx-conf-reload.sh &

filename=/cf-config/current/config/customconf.tar.gz

while true
do
  if [ -f "$filename" ]; then
    file_age=$(($(date +%s) - $(date +%s -r "$filename")))
    echo "File age in sec: $file_age"
    if (( file_age < 20 ));
    then
      echo "New copy of $source_file found. calling reload script."
      /usr/local/bin/nginx-conf-reload.sh &
    fi
  else
      echo "custom.tar.gz missing" >&2
  fi
  sleep 20;
done
