#!/usr/bin/env python3

import subprocess


process = subprocess.Popen(
    ["find", ".", "-type", "f", "-name", "*-main.py", "-exec", "python3", "{}", '\\', ';'],
    stdout=subprocess.PIPE, text=True
)

for file in process.stdout:
    print(f"PROCESSING FILE {file}")
