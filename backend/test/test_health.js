const { main } = require("../packages/live-telemetry/health/health");

(async () => {
  console.log(JSON.stringify(await main({
    http: { method: "GET" }
  }), null, 2));
})();
