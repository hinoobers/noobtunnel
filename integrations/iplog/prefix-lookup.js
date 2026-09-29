'use strict';

// A containing CIDR must be one of the address's network ancestors. Matching
// those exact (family, start_ip, prefix_length) keys uses bgp_prefixes' primary
// index instead of scanning and sorting every earlier address range.
function ancestorPrefixes(parsedIp) {
    const width = parsedIp.family === 4 ? 32 : parsedIp.family === 6 ? 128 : 0;
    if (!width || !Buffer.isBuffer(parsedIp.buffer) || parsedIp.buffer.length !== 16) {
        throw new TypeError('Expected a parsed IPv4 or IPv6 address');
    }
    const network = Buffer.from(parsedIp.buffer);
    const prefixes = [];
    for (let length = width; length >= 0; length--) {
        prefixes.push({ start: Buffer.from(network), length });
        if (length > 0) {
            const bit = 128 - width + length - 1;
            network[Math.floor(bit / 8)] &= ~(1 << (7 - bit % 8));
        }
    }
    return prefixes;
}

function buildRouteLookup(parsedIp) {
    const prefixes = ancestorPrefixes(parsedIp);
    const predicate = prefixes.map(() => '(route.start_ip = ? AND route.prefix_length = ?)').join(' OR ');
    const params = [parsedIp.family];
    for (const prefix of prefixes) params.push(prefix.start, prefix.length);
    params.push(parsedIp.buffer);
    return {
        sql: `SELECT route.prefix, route.prefix_length, route.asn,
            COALESCE(names.name, route.description) AS as_name,
            names.country_code AS as_country_code, route.visibility
        FROM bgp_prefixes AS route
        LEFT JOIN as_names AS names ON names.asn = route.asn
        WHERE route.family = ? AND (${predicate}) AND route.end_ip >= ?
        ORDER BY route.prefix_length DESC, route.visibility DESC
        LIMIT 16`,
        params
    };
}

module.exports = { ancestorPrefixes, buildRouteLookup };
