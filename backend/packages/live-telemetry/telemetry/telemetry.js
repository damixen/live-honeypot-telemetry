const internalCache = new Map();
const CACHE_TTL_MS = 30 * 1000;

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
  internalCache.set(key, {
    value,
    expiresAt: Date.now() + CACHE_TTL_MS,
  });
}

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

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

async function main(args) {

  const origin = getCorsOrigin(args.http.headers || {});

  if (args.http.method === "OPTIONS") {
    return response(
      200,
      { message: "CORS preflight" },
      {
        // Limit which origin can access this endpoint.
        "Access-Control-Allow-Origin": origin,
        // Only allow specific HTTP methods for cross-origin calls.
        "Access-Control-Allow-Methods": "OPTIONS, GET",
        // Only expose required request headers.
        "Access-Control-Allow-Headers": "Content-Type",
        "Vary": "Origin"
      },
    );
  }

  const hostId = args.host_id;
  const mode = args.mode; // latest | daily
  const date = args.date;

  if (!hostId) {
    return response(400, { error: "missing host_id" });
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
    return response(
      200,
      {
        ...cached,
        _cache: "internal-hit",
      },
      { "Access-Control-Allow-Origin": origin },
    );
  }

  // -------------------------
  // UPSTASH FETCH
  // -------------------------
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

  const parsed = JSON.parse(data.result);

  // -------------------------
  // STORE INTERNAL CACHE
  // -------------------------
  setCache(cKey, parsed);

  return response(
    200,
    {
      ...parsed,
      _cache: "miss-upstash",
    },
    { "Access-Control-Allow-Origin": origin },
  );
}

module.exports = { main };
