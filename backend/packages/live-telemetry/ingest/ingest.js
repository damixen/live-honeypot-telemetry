let cache = null;
let updatedAt = null;
const MAX_BYTES = 50 * 1024; // 50 KB

function isValid(payload) {
  return (
    payload &&
    typeof payload.host_id === "string" &&
    typeof payload.date === "string" &&
    typeof payload.events === "number"
  );
}

function buildKey(host_id, report_type, date) {
  let key = null;
  switch (report_type) {
    case "latest":
      key = `telemetry:latest:${host_id}`;
      break;

    case "daily":
      key = `telemetry:daily:${host_id}:${date}`;
      break;

    default:
      throw new Error("Unknown report_type");
  }
  return key;
}

function getTtlSeconds(reportType) {
  switch (reportType) {
    case "latest":
      return parseInt(process.env.UPSTASH_LATEST_TTL_SECONDS ?? "3600", 10);

    case "daily":
      return parseInt(process.env.UPSTASH_DAILY_TTL_SECONDS ?? "-1", 10);

    default:
      throw new Error(`Unsupported report_type: ${reportType}`);
  }
}

const ALLOWED_HOSTS = new Set(
  (process.env.ALLOWED_HOSTS || "hp-do-sfo3").split(",").filter(Boolean),
);

async function main(args) {
  const method = args.http.method;

  // ---- INGEST ----
  if (method === "POST") {
    const payload = args?.data;

    if (!payload || typeof payload !== "object") {
      return {
        statusCode: 400,
        body: { error: "Invalid payload" },
      };
    }

    const report_type = args?.report_type ?? "daily";

    const size = JSON.stringify(args).length;

    if (size > MAX_BYTES) {
      return {
        statusCode: 413,
        body: {
          ok: false,
          error: "Payload too large",
        },
      };
    }

    if (
      typeof payload.host_id !== "string" ||
      payload.host_id.length === 0 ||
      payload.host_id.length > 64 ||
      !/^[A-Za-z0-9_-]{1,64}$/.test(payload.host_id)
    ) {
      return {
        statusCode: 400,
        body: {
          ok: false,
          error: "Invalid host_id",
        },
      };
    }

    if (
      typeof payload.date !== "string" ||
      payload.date.length !== 10 ||
      !/^\d{4}-\d{2}-\d{2}$/.test(payload.date)
    ) {
      return {
        statusCode: 400,
        body: {
          ok: false,
          error: "Invalid date",
        },
      };
    }

    if (!isValid(payload)) {
      return {
        statusCode: 400,
        body: {
          ok: false,
          error: "Invalid schema",
        },
      };
    }

    if (!ALLOWED_HOSTS.has(payload.host_id)) {
      return {
        statusCode: 400,
        body: { error: "Invalid host" },
      };
    }

    if (!Number.isFinite(payload.events) || payload.events < 0) {
      return {
        statusCode: 400,
        body: { error: "Invalid events" },
      };
    }

    if (!["latest", "daily"].includes(report_type)) {
      return {
        statusCode: 400,
        body: { error: "Invalid report type" },
      };
    }

    const key = buildKey(payload.host_id, report_type, payload.date);
    const ttl = getTtlSeconds(report_type);

    let url = `${process.env.UPSTASH_URL}/set/${encodeURIComponent(key)}`;

    if (Number.isFinite(ttl) && ttl > 0) {
      url += `?EX=${ttl}`;
    }

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.UPSTASH_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });
      const text = await response.text();

      if (!response.ok) {
        throw new Error(`Upstash returned ${response.status}`);
      }

      return {
        statusCode: 200,
        body: { ok: true, key },
      };
    } catch (err) {
      console.error(err);

      return {
        statusCode: 503,
        body: {
          ok: false,
          error: "Storage unavailable",
        },
      };
    }
  }

  return {
    statusCode: 405,
    headers: {
      Allow: "POST",
    },
    body: {
      error: "method_not_allowed",
    },
  };
}

module.exports = { main };
