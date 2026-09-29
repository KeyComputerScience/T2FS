#!/bin/bash
set -e

echo "Resource analysis"
cd experiments
python3 measure_resource.py
python3 analyze_handshake.py
python3 analyze_energy.py
python3 attack_validation.py
python3 generate_tables.py
echo "Finished"
