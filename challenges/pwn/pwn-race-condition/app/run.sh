#!/bin/bash
echo "$FLAG" > /root/flag.txt
chmod 400 /root/flag.txt
exec su ctf -c /app/reader
