#!/bin/bash
echo "$FLAG" > /home/ctf/flag.txt
chmod 444 /home/ctf/flag.txt
exec su ctf -c /app/vuln
