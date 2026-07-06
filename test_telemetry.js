const { main } = require("./telemetry");

(async () => {
  console.log(await main({
    host_id: "hp-do-sfo3",
    mode: "latest",
    http: { method: "GET" }
  }));
})();