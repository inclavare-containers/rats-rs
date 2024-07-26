# cert-app

This is a sample application using the rats-rs cert api. This program will first generates the X.509 certificate and verifies the X.509 certificate.

Note: Running in non-TEE environment is not supported due to the need to generate certificates.

## Build cert-app

```sh
cd ./examples/cert-app/
cmake -H. -Bbuild
make -Cbuild all
```

The output binary is located at `./build/cert-app`

## Run cert-app

You can run it in an Occlum instance:

```sh
../../scripts/run_exe_in_occlum.sh ./build/cert-app
```

Or run it directly in a TDX instance

```sh
./build/cert-app
```

## Specify the command line parameters

The options of `cert-app` are as followed:

```txt
    Usage:

        cert-app <options> [arguments]

    Options:

        --no-privkey/-k               Set to enable key pairs generation in rats-rs
        --add-claim/-C key:val        Add a user-defined custom claims
        --attester/-a value           Set the type of quote attester. (Should be one of: coco, auto, sgx-ecdsa, tdx. Default: auto)
        --log-level/-l                Set the log level. (Should be one of: off, error, warn, info, debug, trace. Default: error)
        --help/-h                     Show the usage
```

## debug

The generated certificate will be dumped to `/tmp/cert.pem`(for Occlum, this file is dumped to the root dir of Occlum instance, Look for a string like `occlum instance dir: /root/occlum-instance-house/tmp.Plv9USVFIk` from the output to determine your occlum instance dir).

Here are some code snippets to let you parse the certificate manually from the command line:

- Get content of evidence extension in hex.

    ```sh
    openssl asn1parse -i -in /tmp/cert.pem -inform pem
    ```
    The hex dump is under the `2.23.133.5.4.9` object (`2.23.133.5.4.2` for endorsements).
    
    The data is a byte string of encoded tagged CBOR data, so you can copy and paste it to [cbor.me](https://cbor.me/) to view its contents.

- Calculate the hash value of the certificate public key.

    ```sh
    openssl x509 -inform pem -in /tmp/cert.pem -noout -pubkey | openssl asn1parse -noout -out - | openssl dgst -c -sha256
    ```
    The output is the sha256 hash of SubjectPublicKeyInfo field in the certificate. Now you can compare it manually with the value stored in the evidence extension.
