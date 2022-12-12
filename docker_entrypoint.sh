#!/bin/bash


set -e
pwd

export PYTHONPATH="${PYTHONPATH}"
export PYTHONPATH="${PYTHONPATH}:/src"
python -c "import sys; print(sys.path)"

#exec python3 src/filter.py &
exec python3 src/main.py