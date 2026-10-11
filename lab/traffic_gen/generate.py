"""Finite one-request-per-second benign lab traffic; only fixed authorized IPs."""
import time
import urllib.request

for _ in range(10):
    for url in ("http://172.30.0.10:8000", "http://172.30.0.11:8001"):
        with urllib.request.urlopen(url, timeout=3) as response:  # nosec B310: fixed internal HTTP URLs
            print(response.read(256).decode().strip())
        time.sleep(1)
