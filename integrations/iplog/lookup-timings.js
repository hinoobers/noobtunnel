"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { performance } = require("node:perf_hooks");

const retentionDays = 90;
const dayMs = 24 * 60 * 60 * 1000;
const elapsed = (start) => Math.round((performance.now() - start) * 10) / 10;

function errorDetails(error) {
    return {
        name: String(error?.name || "Error"),
        code: error?.code ? String(error.code) : undefined,
        message: String(error?.message || error).slice(0, 500)
    };
}

// Daily JSONL files survive container restarts and can be inspected without
// querying iplog's database, which may itself be the source of a slow lookup.
function createLookupTimings(directory) {
    let available = true;
    try {
        fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    } catch (error) {
        available = false;
        console.error("Cannot create IP lookup timing directory:", error);
    }

    function prune() {
        if (!available) return;
        const cutoff = Date.now() - retentionDays * dayMs;
        fs.readdir(directory, (error, files) => {
            if (error) return console.warn("Cannot list IP lookup timing files:", error);
            for (const file of files) {
                const match = /^checkip-([0-9]{4}-[0-9]{2}-[0-9]{2})\.jsonl$/.exec(file);
                if (!match || Date.parse(match[1]) >= cutoff) continue;
                fs.unlink(path.join(directory, file), (unlinkError) => {
                    if (unlinkError && unlinkError.code !== "ENOENT") {
                        console.warn("Cannot prune IP lookup timing file:", unlinkError);
                    }
                });
            }
        });
    }
    prune();
    const pruneTimer = setInterval(prune, dayMs);
    pruneTimer.unref?.();

    function write(record) {
        if (!available) return;
        const day = new Date().toISOString().slice(0, 10);
        const file = path.join(directory, "checkip-" + day + ".jsonl");
        fs.appendFile(file, JSON.stringify(record) + "\n", { mode: 0o600 }, (error) => {
            if (error) console.warn("Cannot save IP lookup timing:", error);
        });
    }

    let active = 0;
    function middleware(req, res, next) {
        const started = performance.now();
        const record = {
            kind: "checkip",
            at: new Date().toISOString(),
            requesterIp: req.ip || "",
            queryIp: String(req.query?.ip ?? "").slice(0, 128),
            activeAtStart: ++active,
            stagesMs: {}
        };
        req.lookupTiming = {
            record,
            elapsed: () => elapsed(started),
            async time(stage, operation) {
                const stageStarted = performance.now();
                try {
                    return await operation();
                } finally {
                    record.stagesMs[stage] = elapsed(stageStarted);
                }
            }
        };
        let recorded = false;
        const finish = (closed) => {
            if (recorded) return;
            recorded = true;
            record.totalMs = elapsed(started);
            record.status = res.statusCode;
            record.clientClosed = closed && !res.writableFinished;
            record.activeAtEnd = --active;
            write(record);
        };
        res.once("finish", () => finish(false));
        res.once("close", () => finish(true));
        next();
    }

    return { middleware, write };
}

module.exports = { createLookupTimings, errorDetails };
