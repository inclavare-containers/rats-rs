#!/bin/bash

set -e
set -x

script_dir=`realpath $(dirname $0)`

if [[ $1 == "" ]]; then
    echo "usage:  $0 <program to run> [arguments]"
    exit 1
fi

exe=$1
shift

if [ ! -f $exe ]; then
    echo "file not exit: $exe"
    exit 1
fi

exe=`realpath $exe`
exe_name=`basename $exe`

# initialize a dir for occlum instance
mkdir -p $HOME/occlum-instance-house
dir=`mktemp --tmpdir=$HOME/occlum-instance-house --dry-run`
echo "occlum instance dir: $dir"

# create a occlum instance
occlum new $dir
cd $dir

# copy files related to the $exe into occlum instance
cat << EOF >"$dir"/copy_bom.yaml
includes:
  - base.yaml
targets:
  - target: /bin
    copy:
      - files:
         - $exe
  - target: /opt/occlum/glibc/lib/
    copy:
      - files:
         - /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1
         - /usr/lib/x86_64-linux-gnu/libcurl.so.4 # used by libsgx_default_qcnl_wrapper.so
         - /usr/lib/x86_64-linux-gnu/libcrypt.so.1 # libcrypt.so.1 is required by libcurl.so, and we need to override libcrypt.so.1 provided by occlum to fix /opt/occlum/glibc/lib/libcrypt.so.1: version XCRYPT_2.0 not found
         - /usr/lib/x86_64-linux-gnu/libnss_dns.so.2 # support dns lookup required by libcurl
  - target: /etc/
    copy:
      - files:
         - /etc/sgx_default_qcnl.conf
         - /etc/resolv.conf
  - target: /etc/ssl/certs/
    copy:
      - dirs:
         - /etc/ssl/certs/ # for curl https://
EOF
copy_bom -f "$dir"/copy_bom.yaml --root image --include-dir /opt/occlum/etc/template

# enlarge memory limits
new_json="$(jq '.resource_limits.user_space_size = "800MB" |
        .resource_limits.kernel_space_heap_size = "600MB" |
        .env.default += ["HOME=/root"]' Occlum.json)" && \
        echo "${new_json}" > Occlum.json

# if $RATS_RS_LOG_LEVEL is set, pass it to occlum instance
if [ -n "$RATS_RS_LOG_LEVEL" ]; then
  new_json="$(jq '.env.default += ["RATS_RS_LOG_LEVEL='$RATS_RS_LOG_LEVEL'"]' Occlum.json)" && \
          echo "${new_json}" > Occlum.json
fi

occlum build

cd "$dir"
occlum run /bin/$exe_name "$@"
