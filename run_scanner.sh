#!/bin/bash
cd "$(dirname "$0")"
python3 scanner.py --target 127.0.0.1 --start 1 --end 1024
read -p "Press Enter to exit"
