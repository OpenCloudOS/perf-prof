#!/bin/sh

tag=$1

if [ -z "$tag" ]
then
  echo "Usage: $0 <package tag>" 1>&2
  exit 0
fi

rpmbuild -bb perf-prof.spec \
    --define "version $tag"
