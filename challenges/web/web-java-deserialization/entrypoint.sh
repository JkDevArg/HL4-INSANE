#!/bin/bash
echo "$FLAG" > /app/flag.txt
exec java -jar /app/app.jar
