const internalCache = new Map();

const DEFAULT_CACHE_TTL_SECONDS = 900;

const ttlSeconds = Number(process.env.CACHE_TTL_SECONDS);

const CACHE_TTL_MS = Number.isFinite(ttlSeconds)
  ? ttlSeconds * 1000
  : DEFAULT_CACHE_TTL_SECONDS * 1000;

function cacheKey(hostId, mode, date) {
  let key = `telemetry:${mode}:${hostId}`;
  if (date) {
    key += `:${date}`;
  }
  return key;
}

function getCache(key) {
  const entry = internalCache.get(key);
  if (!entry) return null;

  if (Date.now() > entry.expiresAt) {
    internalCache.delete(key);
    return null;
  }

  return entry.value;
}

function setCache(key, value) {
  if (CACHE_TTL_MS <= 0) {
    return;
  }

  internalCache.set(key, {
    value,
    expiresAt: Date.now() + CACHE_TTL_MS,
  });
}

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    Vary: "Origin",
  };
}

function response(statusCode, body, corsHeaders = {}) {
  return {
    statusCode,
    // DO handles CORS automatically, so we don't need to set headers here for now
    headers: corsHeaders,
    body,
  };
}

const allowedOrigins = [
  "https://gingerpot.damixen.com",
  "https://damixen.github.io",
  "http://localhost:8080",
];

function getCorsOrigin(headers) {
  if (process.env.DISABLE_CORS === "true") {
    return "*";
  }

  const origin = headers.origin;

  if (allowedOrigins.includes(origin)) {
    return origin;
  }
  console.log(`Rejected CORS origin: ${origin}`);
  return "";
}

const allowedHosts = new Set(
  (process.env.ALLOWED_HOSTS || "hp-do-sfo3")
    .split(",")
    .map((h) => h.trim())
    .filter(Boolean),
);

async function main(args) {
  const origin = getCorsOrigin(args.http.headers || {});

  if (args.http.method === "OPTIONS") {
    return response(200, { message: "CORS preflight" }, corsHeaders(origin));
  }

  if (args.http.method !== "GET") {
    return {
      statusCode: 405,
      headers: {
        Allow: "GET",
        ...corsHeaders(origin)
      },
      body: {
        error: "method_not_allowed",
      },
    };
  }

  const hostId = args.host_id;
  const mode = args.mode; // latest | daily
  const date = args.date;

  if (!hostId) {
    return response(400, { error: "missing host_id" });
  }

  if (!allowedHosts.has(hostId)) {
    return response(400, { error: "invalid host_id" });
  }

  const DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;

  if (mode === "daily" && !DATE_REGEX.test(date)) {
    return response(400, { error: "invalid date" });
  }

  let key;

  switch (mode) {
    case "latest":
      key = cacheKey(hostId, mode);
      break;

    case "daily":
      if (!date) {
        return response(400, { error: "missing date for daily mode" });
      }
      key = cacheKey(hostId, mode, date);
      break;

    default:
      return response(400, { error: "invalid mode" });
  }

  const cKey = cacheKey(hostId, mode, date);

  // -------------------------
  // INTERNAL CACHE HIT
  // -------------------------
  const cached = getCache(cKey);

  if (cached) {
    if (process.env.DEBUG === "true") {
      cached = {
        ...cached,
        _cache: "miss-upstash",
      };
    }

    return response(200, cached, corsHeaders(origin));
  }

  // -------------------------
  // UPSTASH FETCH
  // -------------------------
  try {
    const redisUrl = `${process.env.UPSTASH_URL}/get/${encodeURIComponent(key)}`;
    const resp = await fetch(redisUrl, {
      headers: {
        Authorization: `Bearer ${process.env.UPSTASH_TOKEN}`,
        "Content-Type": "application/json",
      },
    });

    const data = await resp.json();
    // console.log(`Upstash response: ${JSON.stringify(data)}`);
    if (!data.result) {
      return response(404, { error: "not found" });
    }

    let parsed = JSON.parse(data.result);

    if (process.env.DEBUG === "true") {
      parsed = {
        ...parsed,
        _cache: "miss-upstash",
      };
    }

    // -------------------------
    // STORE INTERNAL CACHE
    // -------------------------
    setCache(cKey, parsed);

    return response(200, parsed, corsHeaders(origin));
  } catch (err) {
    console.error("Upstash fetch failed", err);

    return response(503, {
      error: "telemetry unavailable",
    });
  }
}

module.exports = { main };
