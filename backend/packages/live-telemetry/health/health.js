const VERSION = "2026.08.0";

async function main(args) {
  const method = args.http.method;
  if (method === "GET") {
    return {
      statusCode: 200,
      body: {
        status: "ok",
        service: "gingerpot-telemetry",
        version: VERSION,
        timestamp: new Date().toISOString(),
      },
    };
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
