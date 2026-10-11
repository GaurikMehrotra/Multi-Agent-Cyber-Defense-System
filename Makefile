PYTHON ?= python
.PHONY: setup test lint audit safety demo detection-eval agent-eval sensors core migrate agents lab clean
setup:
	$(PYTHON) -m pip install -r requirements.txt
	test -f .env || $(PYTHON) scripts/init_env.py
	mkdir -p runtime data/pcaps data/zeek data/suricata artifacts
test:
	$(PYTHON) -m pytest -q
lint:
	$(PYTHON) -m ruff check src app scripts tests migrations
	$(PYTHON) -m ruff format --check src app scripts tests migrations
	$(PYTHON) -m bandit -r src app scripts migrations -q
audit:
	$(PYTHON) scripts/audit_dependencies.py
safety:
	$(PYTHON) -m src.eval.safety_eval
demo:
	PYTHONPATH=. $(PYTHON) scripts/demo.py
detection-eval:
	$(PYTHON) -m src.eval.run_detection
agent-eval:
	$(PYTHON) -m src.eval.comparison
sensors:
	$(PYTHON) scripts/benign_pcap.py
	PYTHONPATH=. $(PYTHON) scripts/sensors.py data/pcaps/benign.pcap
core:
	docker compose --profile core up -d postgres
migrate:
	$(PYTHON) scripts/migrate.py
agents:
	docker compose --profile agents up -d api worker dashboard
lab:
	docker compose --profile lab up -d web web2 nmap
clean:
	docker compose --profile core --profile agents --profile lab down
