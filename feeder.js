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

async function main(args) {

    const method = args.http.method;

    // ---- INGEST ----
    if (method === "POST") {

        const payload = args?.data;

        const size = JSON.stringify(args).length;

        if (size > MAX_BYTES) {
            return {
                statusCode: 413,
                body: {
                    ok: false,
                    error: "Payload too large"
                }
            };
        }

        if (
            typeof payload.host_id !== "string" ||
            payload.host_id.length === 0 ||
            payload.host_id.length > 64 ||
            (!/^[A-Za-z0-9_-]{1,64}$/.test(payload.host_id))
        ) {
            return {
                statusCode: 400,
                body: {
                    ok: false,
                    error: "Invalid host_id"
                }
            };
        }

        if (
            typeof payload.date !== "string" ||
            payload.date.length !== 10 ||
            (!/^\d{4}-\d{2}-\d{2}$/.test(payload.date))
        ) {
            return {
                statusCode: 400,
                body: {
                    ok: false,
                    error: "Invalid date"
                }
            };
        }

        if (!isValid(payload)) {
            return {
                statusCode: 400,
                body: {
                    ok: false,
                    error: "Invalid schema"
                }
            };
        }

        const key = `stats:${payload.host_id}:${payload.date}`;
        const ttl = Number.parseInt(
            process.env.UPSTASH_TTL_SECONDS ?? "-1",
            10
        );

        let url =
            `${process.env.UPSTASH_URL}/set/${encodeURIComponent(key)}`;

        if (Number.isFinite(ttl) && ttl > 0) {
            url += `?EX=${ttl}`;
        }
        console.log(url);
        console.log(encodeURIComponent(key));
        console.log(ttl)
        const response = await fetch(
            url,
            {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${process.env.UPSTASH_TOKEN}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(payload)
            }
        );
        const text = await response.text();
        console.log(response.status);
        console.log(text.error);

        if (!response.ok) {
            throw new Error(`Upstash returned ${response.status}`);
        }

        return {
            statusCode: 200,
            body: { ok: true, key }
        };
    }

    // ---- TELEMETRY ----
    if (method === "GET") {
        if (!cache) {
            return { statusCode: 503, body: { error: "no_data" } };
        }

        return {
            statusCode: 200,
            headers: {
                "Access-Control-Allow-Origin": "*"
            },
            body: {
                ...cache,
                updated_at: updatedAt
            }
        };
    }

    return { statusCode: 404, body: { error: "not_found" } };
};