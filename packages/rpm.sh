#!/bin/sh

tag=$1

if [ -z "$tag" ]
then
  echo "Usage: $0 <package tag>" 1>&2
  exit 0
fi

rpmbuild -bb rpm.spec \
    --define "name perf-prof" \
    --define "version $tag"
