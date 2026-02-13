@echo off
curl http://127.0.0.1:8000/ > server_status.txt 2>&1
type server_status.txt
