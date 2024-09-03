# openssl-hook

A helper library for embedding rats-rs into a programs without recompiling it from source code, with the help of `LD_PRELOAD`. 

## How to use

We have tested it with `curl` and `nginx`.

### nginx

In a TD VM, we launch a simple nginx server which holds a default page, with https enabled.

Note that rats-rs should be compiled in `tdx` mode.

```sh
# create a nginx configuration file, and save it as ~/nginx.conf
cat <<EOF > ~/nginx.conf
daemon off;
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 5m;
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256;

    server {
        listen 1234 ssl;
        server_name your_domain.com;

        # please place a dump cert and private key files in this location, our hook will replace this with its own files.  
        ssl_certificate /root/cert.pem;
        ssl_certificate_key /root/key.pem;

        # rest of your server configuration
    }
}
EOF

# launch the nginx server
LD_PRELOAD=/root/rats-rs/target/debug/libopenssl_hook.so nginx -c ~/nginx.conf
```

### curl

Here is the client side, no TEE is required, so you can compile rats-rs with `host` mode.

```sh
LD_PRELOAD=/root/rats-rs/target/debug/libopenssl_hook.so curl --resolve rats-rs:1234:172.17.0.2 https://rats-rs:1234/
```

> In the current implementation, the CN field is always `rats-rs`. However, the curl would compare `CN` field in cert with hostname in url. Here we use `--resolve rats-rs:1234:<nginx_ip_address>` to bypass the check from curl. 

## Debug

You can use `gdb` to to debug this library.

```sh
gdb --args env LD_PRELOAD=/usr/share/rats-rs/samples/libopenssl-hook_lib.so <your-target-app>
```

You can use `ltrace` to trace openssl 
```sh
LD_PRELOAD=/root/rats-rs/target/debug/libopenssl_hook.so ltrace -e "SSL_*" <your-target-app>
```

## Noted 
1. your target program may be stuck at setting certificate for a while since it takes time for `rats-rs` to generate a certificate. 
2. openssl-hook hook **ENTIRE** certificate verify procedure to adapt as many executables, care should be taken if your target app also changes the verify callback.
