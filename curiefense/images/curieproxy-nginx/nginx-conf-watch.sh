#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
  set -o xtrace
fi

echo "WATCH-CUSTOMCONF: Blindly calling reload script at start"
/usr/local/bin/nginx-conf-reload.sh &

confarchive=/cf-config/current/config/customconf.tar.gz

while true
do
  if [ -f "$confarchive" ]; then
    file_age=$(($(date +%s) - $(date +%s -r "$confarchive")))
    echo "WATCH-CUSTOMCONF: File age in sec: $file_age"
    if (( file_age < 20 ));
    then
      echo "WATCH-CUSTOMCONF: New copy of $confarchive found. calling reload script."
      /usr/local/bin/nginx-conf-reload.sh &
    fi
  else
      echo "WATCH-CUSTOMCONF: ${confarchive} missing" >&2
  fi
  sleep 20;
done
