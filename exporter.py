from elasticsearch import Elasticsearch
from datetime import datetime, timedelta, timezone
import json
import os
import sys

ES_HOST = os.getenv("ES_HOST", "http://localhost:64298")
INDEX = os.getenv("ES_INDEX", "logstash-*")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "./telemetry.json")

es = Elasticsearch(ES_HOST)


# ---------------------------
# TIME RANGE
# ---------------------------
def get_time_range():
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=24)
    return start, now


def iso(dt):
    return dt.isoformat()


# ---------------------------
# FETCH DATA
# ---------------------------
def fetch():
    start, end = get_time_range()

    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    # time window
                    {"range": {"@timestamp": {"gte": iso(start), "lte": iso(end)}}},
                    # -------------------------------------------------
                    # 🔥 PRIMARY FILTER: ONLY COWRIE EVENTS
                    # -------------------------------------------------
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
                            ]
                        }
                    },
                ]
            }
        },
        "aggs": {
            # total events (better than hits.total in logstash)
            "events_24h": {"value_count": {"field": "uuid.keyword"}},
            # unique attackers
            "unique_ips": {"cardinality": {"field": "src_ip.keyword"}},
            # attacker countries (geoip)
            "countries": {"terms": {"field": "geoip.country_name.keyword", "size": 10}},
            # honeypot types (still useful for future expansion)
            "honeypot_types": {"terms": {"field": "type.keyword", "size": 5}},
            # activity sparkline
            "sparkline": {
                "date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}
            },
            # protocol breakdown (SSH etc.)
            "protocols": {"terms": {"field": "protocol.keyword", "size": 5}},
        },
    }

    return es.search(index=INDEX, body=query)


# ---------------------------
# TRANSFORM
# ---------------------------
def transform(resp, host):
    aggs = resp["aggregations"]

    sparkline = [b["doc_count"] for b in aggs["sparkline"]["buckets"]]

    countries = [
        {"country": b["key"], "count": b["doc_count"]}
        for b in aggs["countries"]["buckets"]
    ]

    protocols = [
        {"protocol": b["key"], "count": b["doc_count"]}
        for b in aggs["protocols"]["buckets"]
    ]

    return {
        "host_id": host,
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "events_24h": aggs["events_24h"]["value"],
        "unique_ips": aggs["unique_ips"]["value"],
        "countries": countries,
        "protocols": protocols,
        "honeypot_types": [
            {"type": b["key"], "count": b["doc_count"]}
            for b in aggs["honeypot_types"]["buckets"]
        ],
        "sparkline": sparkline,
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
    resp = fetch()
    arguments = sys.argv[1:]
    host = arguments[0]
    data = transform(resp, host)
    write(data)


if __name__ == "__main__":
    main()
