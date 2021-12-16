# rekt
server that rekts

```cc main.c -O3 -lssl -lcrypto -D DEBUG``` to compile with Verbose Output

```cc main.c -O3 -lssl -lcrypto -D DEBUG -D EXPERIMENTAL``` to compile with Verbose Output and some non-stable features

# Goals
Rekt doesn't aim to be fastest on the west, but it tries to be fast enough while keeping K.I.S.S. principles at it's best.

Currently rekt works as static web server, responding only to `GET` method


OpenSSL cert/key generation oneliner: <br>
```openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -nodes -subj '/CN=asskey' -days 3650 ```

