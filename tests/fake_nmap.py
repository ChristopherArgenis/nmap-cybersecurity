#!/usr/bin/env python3
"""Sustituto de nmap para pruebas: NO toca la red.

Imprime una salida simulada y copia el XML de ejemplo en la ruta de -oX.
"""
import shutil
import sys
import time
from pathlib import Path

args = sys.argv[1:]
xml_out = args[args.index("-oX") + 1]
print("Starting Nmap 7.95 (simulado) ( https://nmap.org )", flush=True)
print("Stats: 0:00:01 elapsed; SYN Stealth Scan Timing: About 50.00% done", flush=True)
if "SLOW" in args:
    time.sleep(30)
shutil.copy(Path(__file__).parent / "fixtures" / "sample_scan.xml", xml_out)
print("Nmap done: 2 IP addresses (2 hosts up) scanned in 12.34 seconds", flush=True)
