from elasticsearch import Elasticsearch
from elasticsearch import ApiError
from elastic_transport import ConnectionError as ESConnectionError
from elastic_transport import ConnectionTimeout
from datetime import datetime, timedelta, timezone
import json
import os
import sys
import time

ES_PORT = os.getenv("ES_PORT", "64298")
ES_HOST = os.getenv("ES_HOST", f"http://localhost:{ES_PORT}")
INDEX = os.getenv("ES_INDEX", "logstash-*")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "./telemetry.json")
TIME_MODE = os.getenv("TIME_MODE", "daily")  # daily | weekly | last24h

TARGET_DATE = os.getenv("TARGET_DATE")  # YYYY-MM-DD (optional)
TARGET_WEEK = os.getenv("TARGET_WEEK")  # YYYY-Www (optional

es = Elasticsearch(ES_HOST)


# ---------------------------
# TIME RANGE LOGIC
# ---------------------------
def get_time_range():
    now = datetime.now(timezone.utc)

    # ---------------------------
    # WEEKLY BACKFILL MODE
    # ---------------------------
    if TARGET_WEEK:
        if TIME_MODE != "weekly":
            raise ValueError("TARGET_WEEK requires TIME_MODE=weekly")

        try:
            year, week = TARGET_WEEK.split("-W")
            start = datetime.fromisocalendar(
                int(year),
                int(week),
                1,  # Monday
            ).replace(tzinfo=timezone.utc)

        except ValueError:
            raise ValueError(
                f"Invalid TARGET_WEEK: {TARGET_WEEK}. "
                "Expected format YYYY-Www, e.g. 2026-W35."
            )

        end = start + timedelta(days=7)

        return start, end, TARGET_WEEK, "1w"

    # ---------------------------
    # DAILY BACKFILL MODE
    # ---------------------------
    if TARGET_DATE:
        start = datetime.strptime(
            TARGET_DATE,
            "%Y-%m-%d",
        ).replace(tzinfo=timezone.utc)

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
    # WEEKLY MODE
    # ---------------------------
    if TIME_MODE == "weekly":
        today_start = datetime(
            now.year,
            now.month,
            now.day,
            tzinfo=timezone.utc,
        )

        # Monday = 0, Sunday = 6
        current_week_start = today_start - timedelta(days=today_start.weekday())

        # Previous complete Monday-Sunday week
        start = current_week_start - timedelta(days=7)
        end = current_week_start

        # ISO week identifier, e.g. 2026-W36
        date_str = start.strftime("%G-W%V")

        return start, end, date_str, "1w"

    # ---------------------------
    # DAILY MODE (DEFAULT)
    # ---------------------------
    today_start = datetime(
        now.year,
        now.month,
        now.day,
        tzinfo=timezone.utc,
    )

    start = today_start - timedelta(days=1)
    end = today_start

    date_str = (today_start - timedelta(days=1)).strftime("%Y-%m-%d")

    return start, end, date_str, "1d"


def iso(dt):
    return dt.isoformat()


# ---------------------------
# INDEX COVERAGE
# ---------------------------
def get_index_name(date):
    return f"logstash-{date:%Y.%m.%d}"


def check_data_coverage(start, end):
    current = start

    while current < end:
        index = get_index_name(current)

        print(f"Checking Elasticsearch index: {index}")

        if not es.indices.exists(index=index):
            raise RuntimeError(f"Required Elasticsearch index does not exist: {index}")

        current += timedelta(days=1)


# ---------------------------
# FETCH DATA
# ---------------------------
def fetch(start, end, interval, retries=5, base_delay=10):
    sparkline_interval = "1d" if interval == "1w" else "1h"

    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": iso(start),
                                "lt": iso(end),
                            }
                        }
                    },
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
            "countries": {
                "terms": {
                    "field": "geoip.country_name.keyword",
                    "size": 10,
                }
            },
            "honeypot_types": {
                "terms": {
                    "field": "type.keyword",
                    "size": 5,
                }
            },
            "sparkline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": sparkline_interval,
                }
            },
            "protocols": {
                "terms": {
                    "field": "protocol.keyword",
                    "size": 5,
                }
            },
            "ports": {
                "terms": {
                    "field": "dest_port",
                    "size": 5,
                }
            },
            "as": {
                "terms": {
                    "field": "geoip.asn",
                    "size": 10,
                },
                "aggs": {
                    "as_org": {
                        "terms": {
                            "field": "geoip.as_org.keyword",
                            "size": 1,
                        }
                    },
                    "countries": {
                        "terms": {
                            "field": "geoip.country_name.keyword",
                            "size": 10,
                        }
                    },
                },
            },
        },
    }

    for attempt in range(1, retries + 1):
        try:
            print(f"Fetching Elasticsearch data " f"(attempt {attempt}/{retries})...")

            return es.options(request_timeout=60).search(index=INDEX, body=query)

        except ESConnectionError as e:
            retryable = True
            error = f"connection error: {e}"

        except ApiError as e:
            retryable = e.status_code == 503
            error = f"Elasticsearch API error " f"{e.status_code}: {e}"

        except (ESConnectionError, ConnectionTimeout) as e:
            retryable = True
            error = f"connection error: {e}"

        if not retryable:
            print(f"ERROR: Non-retryable Elasticsearch error: " f"{error}")
            raise RuntimeError(error)

        if attempt == retries:
            print(
                f"ERROR: Elasticsearch request failed after "
                f"{retries} attempts: {error}"
            )
            raise RuntimeError(error)

        delay = base_delay * (2 ** (attempt - 1))

        print(f"WARNING: Elasticsearch unavailable: {error}")
        print(f"Retrying in {delay} seconds...")

        time.sleep(delay)

    raise RuntimeError("Elasticsearch request failed")


# ---------------------------
# TRANSFORM
# ---------------------------
def transform(
    resp,
    host,
    start,
    end,
    date_str,
    interval,
):
    aggs = resp["aggregations"]

    return {
        "host_id": host,
        # Logical date / period identifier
        "date": date_str,
        # Execution metadata
        "updated_at": datetime.now(timezone.utc).isoformat(),
        # Time semantics
        "time_interval": interval,
        "window_start": iso(start),
        "window_end": iso(end),
        # Metrics
        "events": resp["hits"]["total"]["value"],
        "unique_ips": aggs["unique_ips"]["value"],
        "countries": [
            {
                "country": bucket["key"],
                "count": bucket["doc_count"],
            }
            for bucket in aggs["countries"]["buckets"]
        ],
        "protocols": [
            {
                "protocol": bucket["key"],
                "count": bucket["doc_count"],
            }
            for bucket in aggs["protocols"]["buckets"]
        ],
        "ports": [bucket["key"] for bucket in aggs["ports"]["buckets"]],
        "honeypot_types": [
            {
                "type": bucket["key"],
                "count": bucket["doc_count"],
            }
            for bucket in aggs["honeypot_types"]["buckets"]
        ],
        "as": [
            {
                "asn": bucket["key"],
                "as_org": (
                    bucket["as_org"]["buckets"][0]["key"]
                    if bucket["as_org"]["buckets"]
                    else None
                ),
                "events": bucket["doc_count"],
                "countries": [
                    {
                        "country": country["key"],
                        "events": country["doc_count"],
                    }
                    for country in bucket["countries"]["buckets"]
                ],
            }
            for bucket in aggs["as"]["buckets"]
        ],
        "sparkline": [bucket["doc_count"] for bucket in aggs["sparkline"]["buckets"]],
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

    print(
        f"Exporting {interval} report: " f"{date_str} " f"({iso(start)} -> {iso(end)})"
    )

    # Weekly reports require every daily source index
    # to exist before aggregation.
    if interval == "1w":
        check_data_coverage(start, end)

    resp = fetch(start, end, interval)

    data = transform(
        resp,
        host,
        start,
        end,
        date_str,
        interval,
    )

    write(data)

    print(f"Export completed successfully: " f"{OUTPUT_FILE}")


if __name__ == "__main__":
    main()
