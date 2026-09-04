#!/bin/bash
# Used to build and serve blog locally in a container.
# This script is executed via `CMD` in the `Containerfile`
#
# I did it this way so I can bake `bundle install` and serving
# the blog into the container. This gives me more flexibility to
# invoke the container AND mount my blog via volumes instead of
# rebuilding the container and copying the files into a layer.
cd /srv/jekyll
bundle install
bundle exec jekyll serve --host 0.0.0.0

