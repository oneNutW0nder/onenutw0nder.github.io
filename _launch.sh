#!/bin/bash
podman run --rm -it -p 4000:4000 -v $PWD:/srv/jekyll blog
