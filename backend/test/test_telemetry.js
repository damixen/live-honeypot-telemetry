const { main } = require("../packages/live-telemetry/telemetry/telemetry");

(async () => {
  console.log(JSON.stringify(await main({
    host_id: "hp-do-sfo3",
    mode: "latest",
    http: { method: "GET" }
  }), null, 2));
})();
