# /bin/bash

docker create --name manson flexstatmain/balance:v1
docker cp dummy:/var/lib/tor/configs .
docker rm -f manson
