#!/bin/sh
python /app/init_db.py
exec python /app/app.py
