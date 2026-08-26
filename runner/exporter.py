from elasticsearch import Elasticsearch
from elasticsearch import ApiError
from elastic_transport import ConnectionError as ESConnectionError
from datetime import datetime, timedelta, timezone
import json
import os
import sys
import time

ES_PORT = os.getenv("ES_PORT", "64298")
ES_HOST = os.getenv("ES_HOST", f"http://localhost:{ES_PORT}")
INDEX = os.getenv("ES_INDEX", "logstash-*")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "./telemetry.json")
TIME_MODE = os.getenv("TIME_MODE", "daily")  # daily | last24h
TARGET_DATE = os.getenv("TARGET_DATE")  # YYYY-MM-DD (optional)

es = Elasticsearch(ES_HOST)


# ---------------------------
# TIME RANGE LOGIC
# ---------------------------
def get_time_range():
    now = datetime.now(timezone.utc)

    # ---------------------------
    # BACKFILL MODE
    # ---------------------------
    if TARGET_DATE:
        start = datetime.strptime(TARGET_DATE, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        end = start + timedelta(days=1)

        return start, end, TARGET_DATE, "1d"

    # ---------------------------
    # ROLLING 24H MODE
    # ---------------------------
    if TIME_MODE == "last24h":
        end = now
        start = now - timedelta(hours=24)

        date_str = now.strftime("%Y-%m-%d")
        return start, end, date_str, "24h"

    # ---------------------------
    # DAILY MODE (DEFAULT)
    # ---------------------------
    today_start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)

    start = today_start - timedelta(days=1)
    end = today_start

    date_str = (today_start - timedelta(days=1)).strftime("%Y-%m-%d")

    return start, end, date_str, "1d"


def iso(dt):
    return dt.isoformat()


# ---------------------------
# FETCH DATA
# ---------------------------
def fetch(start, end, retries=5, base_delay=10):

    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": iso(start), "lt": iso(end)}}},
                    {
                        "terms": {
                            "type.keyword": [
                                "Cowrie",
                                "Tanner",
                                "Wordpot",
                                "Dionaea",
                                "ElasticPot",
                                "Redishoneypot",
                                "Adbhoney",
                                "Heralding",
                                "Sentrypeer",
                            ]
                        }
                    },
                ]
            }
        },
        "aggs": {
            "unique_ips": {"cardinality": {"field": "src_ip.keyword"}},
            "countries": {"terms": {"field": "geoip.country_name.keyword", "size": 10}},
            "honeypot_types": {"terms": {"field": "type.keyword", "size": 5}},
            "sparkline": {
                "date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}
            },
            "protocols": {"terms": {"field": "protocol.keyword", "size": 5}},
            "ports": {"terms": {"field": "dest_port", "size": 5}},
        },
    }

    for attempt in range(1, retries + 1):
        try:
            print(f"Fetching Elasticsearch data (attempt {attempt}/{retries})...")
            return es.search(index=INDEX, body=query)

        except ESConnectionError as e:
            retryable = True
            error = f"connection error: {e}"

        except ApiError as e:
            retryable = e.status_code == 503
            error = f"Elasticsearch API error {e.status_code}: {e}"

        if not retryable:
            print(f"ERROR: Non-retryable Elasticsearch error: {error}")
            raise RuntimeError(error)

        if attempt == retries:
            print(
                f"ERROR: Elasticsearch request failed after "
                f"{retries} attempts: {error}"
            )
            raise

            delay = base_delay * (2 ** (attempt - 1))

            print(f"WARNING: Elasticsearch unavailable: {e}")
            print(f"Retrying in {delay} seconds...")

            time.sleep(delay)

    return es.search(index=INDEX, body=query)


# ---------------------------
# TRANSFORM
# ---------------------------
def transform(resp, host, start, end, date_str, interval):

    aggs = resp["aggregations"]

    return {
        "host_id": host,
        # IMPORTANT: logical date (for Redis key + graphs)
        "date": date_str,
        # execution metadata
        "updated_at": datetime.now(timezone.utc).isoformat(),
        # time semantics
        "time_interval": interval,
        "window_start": iso(start),
        "window_end": iso(end),
        # metrics
        "events": resp["hits"]["total"]["value"],
        "unique_ips": aggs["unique_ips"]["value"],
        "countries": [
            {"country": b["key"], "count": b["doc_count"]}
            for b in aggs["countries"]["buckets"]
        ],
        "protocols": [
            {"protocol": b["key"], "count": b["doc_count"]}
            for b in aggs["protocols"]["buckets"]
        ],
        "ports": [b["key"] for b in aggs["ports"]["buckets"]],
        "honeypot_types": [
            {"type": b["key"], "count": b["doc_count"]}
            for b in aggs["honeypot_types"]["buckets"]
        ],
        "sparkline": [b["doc_count"] for b in aggs["sparkline"]["buckets"]],
    }


# ---------------------------
# WRITE OUTPUT
# ---------------------------
def write(data):
    tmp = OUTPUT_FILE + ".tmp"

    with open(tmp, "w") as f:
        json.dump(data, f)

    os.replace(tmp, OUTPUT_FILE)


# ---------------------------
# MAIN
# ---------------------------
def main():
    host = sys.argv[1]

    start, end, date_str, interval = get_time_range()

    resp = fetch(start, end)

    data = transform(resp, host, start, end, date_str, interval)

    write(data)


if __name__ == "__main__":
    main()
