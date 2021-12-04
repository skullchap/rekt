# rekt
server that rekts

```cc main.c -O3 -D DEBUG``` to compile with Verbose Output

```cc main.c -O3 -D DEBUG -D EXPERIMENTAL``` to compile with Verbose Output and Experimental features

# Goals
Rekt doesn't aim to be fastest on the west, but it tries to be fast enough while keeping K.I.S.S. principles at it's best

Currently rekt works as static web server, responding only to `GET` method

# TODOs
* <strike>simple http interface that shows directory files, and allows access them</strike>
* `POST` method recognition
* `POST` forms parse
* `Content-Type` header recognition
* Populating HTTP response codes with most used codes like 301,302,400,500
* JSON parsing
* simple HTTP templating 
* <strike>(maybe) adjust stack size for child forked processes.</strike>
* (maybe) switch `fork()` to `select()` or `poll()` for multiplexing. If complexity over increased and performance is not that different, stick to `fork()`
