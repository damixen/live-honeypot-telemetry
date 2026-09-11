# Live HoneyPot Runner

Export telemetry from Elasticsearch

# Running

```bash
 sudo apt install python3.12-venv
 python3 -m venv .venv
 source .venv/bin/activate
 pip install elasticsearch

 TIME_MODE=daily python3 exporter.py <host_name>
```
