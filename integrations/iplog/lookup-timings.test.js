"use strict";

const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");
const { createLookupTimings } = require("./lookup-timings");

async function readRecords(directory) {
    const file = path.join(directory, "checkip-" + new Date().toISOString().slice(0, 10) + ".jsonl");
    for (let attempt = 0; attempt < 40; attempt++) {
        try {
            const contents = await fs.readFile(file, "utf8");
            if (contents.trim().endsWith("}")) {
                return contents.trim().split("\n").map((line) => JSON.parse(line));
            }
        } catch (error) {
            if (error.code !== "ENOENT") throw error;
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error("Timing record was not written");
}

test("records completed lookups and their stages on disk", async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), "iplog-timings-"));
    try {
        const recorder = createLookupTimings(directory);
        const req = { ip: "192.0.2.1", query: { ip: "1.1.1.1" } };
        const res = new EventEmitter();
        res.statusCode = 200;
        res.writableFinished = true;
        let called = false;
        recorder.middleware(req, res, () => { called = true; });
        assert.equal(called, true);
        await req.lookupTiming.time("databaseLookup", async () => {
            await new Promise((resolve) => setTimeout(resolve, 5));
        });
        req.lookupTiming.record.cache = "miss";
        res.emit("finish");
        const records = await readRecords(directory);
        assert.equal(records.length, 1);
        assert.equal(records[0].kind, "checkip");
        assert.equal(records[0].queryIp, "1.1.1.1");
        assert.equal(records[0].status, 200);
        assert.equal(records[0].cache, "miss");
        assert.ok(records[0].stagesMs.databaseLookup >= 0);
        assert.ok(records[0].totalMs >= records[0].stagesMs.databaseLookup);
        assert.equal(records[0].activeAtEnd, 0);
    } finally {
        await fs.rm(directory, { recursive: true, force: true });
    }
});
