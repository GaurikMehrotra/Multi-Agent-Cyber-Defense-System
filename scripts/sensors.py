"""Process one PCAP into isolated, content-addressed sensor output directories."""

import argparse
import hashlib
import json
from pathlib import Path

from src.sensors.suricata_runner import IMAGE as SURI_IMAGE
from src.sensors.suricata_runner import run as suricata
from src.sensors.zeek_runner import IMAGE as ZEEK_IMAGE
from src.sensors.zeek_runner import run as zeek

parser = argparse.ArgumentParser()
parser.add_argument("pcap")
args = parser.parse_args()
pcap = Path(args.pcap)
identity = hashlib.sha256(pcap.read_bytes()).hexdigest()
config_digest = hashlib.sha256(
    b"".join(path.read_bytes() for path in sorted(Path("configs").glob("*")) if path.is_file())
).hexdigest()
run_id = hashlib.sha256((identity + config_digest + SURI_IMAGE + ZEEK_IMAGE).encode()).hexdigest()[
    :16
]
zeek_dir = Path("data/zeek") / run_id
suri_dir = Path("data/suricata") / run_id
zeek(pcap, zeek_dir)
suricata(pcap, suri_dir)
manifest = {
    "pcap_sha256": identity,
    "config_sha256": config_digest,
    "zeek_image": ZEEK_IMAGE,
    "suricata_image": SURI_IMAGE,
    "zeek": str(zeek_dir),
    "eve": str(suri_dir / "eve.json"),
}
Path("runtime").mkdir(exist_ok=True)
Path("runtime/sensors-latest.json").write_text(json.dumps(manifest, indent=2))
print(json.dumps({"run_id": run_id, "zeek": manifest["zeek"], "eve": manifest["eve"]}))
