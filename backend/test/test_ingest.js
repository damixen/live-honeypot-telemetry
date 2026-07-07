const { main } = require("../packages/live-telemetry/ingest/ingest");

(async () => {
  console.log(await main(
    {
      "http": {
        "method": "POST"
      },
      "data": {
        "host_id": "hp-do-sfo3",
        "events": 123,
        "date": "2099-07-04"
      },
      "report_type": "daily"

    }
  ));
})();
