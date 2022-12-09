# /bin/bash

docker run -d --name manson flexstatmain/gobalance:v2
docker exec manson ./gobalance generate-config
docker exec manson cp config.toml /var/lib/tor/configs
docker exec manson /bin/sh -c 'cp *.key /var/lib/tor/configs'
docker cp manson:/var/lib/tor/configs .
