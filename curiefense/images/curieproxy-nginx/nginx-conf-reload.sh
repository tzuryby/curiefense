#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

source_file="/cf-config/current/config/customconf.tar.gz"
target_dir="/etc/nginx/conf.d"
temp_dir="/tmp/current-conf"

if [ -f "$source_file" ]; then
  mkdir -p ${temp_dir}
  rm -rf "${temp_dir:?}/"*
  cp -a ${target_dir}/. ${temp_dir}/
  rm -rf "${target_dir:?}/"*
  echo "RELOAD-CUSTOMCODE: Extract $source_file into $target_dir"
  tar xzf ${source_file} -C ${target_dir}
  echo "RELOAD-CUSTOMCODE: Test Nginx with new configuration"
  nginx -t
  ## check exit code of previous command
  retVal=$?
  if [ $retVal -ne 0 ];
  then
    echo "RELOAD-CUSTOMCODE: Nginx failed, restore config files" >&2
    cp -a  ${temp_dir}/. ${target_dir}/
    cp ${target_dir}/lua/customcode.lua /lua/customcode.lua
  else
      echo reloading nginx
      nginx -s reload
      echo "RELOAD-CUSTOMCODE: Nginx reloaded with the new config"
  fi
else
  echo "RELOAD-CUSTOMCODE: ${source_file} does not exist. Exiting $0" >&2
  exit
fi
