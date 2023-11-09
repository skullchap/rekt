# rekt
server that rekts

```cc main.c -O3 -lssl -lcrypto -D DEBUG``` to compile with Verbose Output

```cc main.c -O3 -lssl -lcrypto -D DEBUG -D EXPERIMENTAL``` to compile with Verbose Output and some non-stable features

OpenSSL cert/key generation oneliner: <br>
```openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -nodes -subj '/CN=asskey' -days 3650 ```

