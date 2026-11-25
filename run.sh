#!/bin/bash
# RBACLens - one command to open the menu (Linux / macOS)
cd "$(dirname "$0")"
python3 run.py scan "$@"
