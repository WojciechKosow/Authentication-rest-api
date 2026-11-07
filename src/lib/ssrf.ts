import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { BlockList, isIP } from "node:net";

/**
 * SSRF protection for outbound calls to developer-configured URLs.
 *
 * 1. Static URL validation (scheme, credentials, IP literals, local hostnames).
 * 2. Connect-time DNS validation: every resolved address is checked right
 *    before the socket connects, which also defeats DNS rebinding.
 * Redirects are never followed by the integration client.
 */

const blocked = new BlockList();
// IPv4 special-purpose ranges (RFC 6890 and friends)
for (const [net, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) {
  blocked.addSubnet(net, prefix, "ipv4");
}
// IPv6 special-purpose ranges
for (const [net, prefix] of [
  ["::", 96], // unspecified, loopback and deprecated IPv4-compatible addresses
  ["64:ff9b::", 96],
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["fc00::", 7],
  ["fe80::", 10],
  ["fec0::", 10],
  ["ff00::", 8],
] as const) {
  blocked.addSubnet(net, prefix, "ipv6");
}

export function isPublicIp(address: string): boolean {
  const family = isIP(address);
  // BlockList matches IPv4-mapped IPv6 (::ffff:a.b.c.d / ::ffff:7f00:1) against IPv4 rules.
  if (family === 4) return !blocked.check(address, "ipv4");
  if (family === 6) return !blocked.check(address, "ipv6");
  return false;
}

export class UnsafeUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsafeUrlError";
  }
}

/** Validate a developer-provided URL. `allowPrivate` is a DEV/TEST-ONLY escape hatch. */
export function assertSafeUrl(raw: string, allowPrivate: boolean): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UnsafeUrlError("URL is not valid");
  }
  if (url.protocol !== "https:" && !(allowPrivate && url.protocol === "http:")) {
    throw new UnsafeUrlError("URL must use https://");
  }
  if (url.username || url.password) throw new UnsafeUrlError("URL must not contain credentials");
  if (url.hash) throw new UnsafeUrlError("URL must not contain a fragment");
  if (raw.length > 2048) throw new UnsafeUrlError("URL is too long");
  if (allowPrivate) return url;

  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (isIP(host)) {
    if (!isPublicIp(host)) throw new UnsafeUrlError("URL points to a private or reserved address");
  } else {
    if (!host.includes(".")) throw new UnsafeUrlError("URL host must be a public domain name");
    if (/(^|\.)(localhost|local|internal|localdomain|home|lan|intranet|corp|railway\.internal)$/.test(host)) {
      throw new UnsafeUrlError("URL host must be a public domain name");
    }
  }
  return url;
}

type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

/** `lookup` implementation for socket connections that refuses non-public addresses. */
export function safeLookup(hostname: string, options: { all?: boolean } | number | undefined, callback: LookupCallback): void {
  const wantAll = typeof options === "object" && options !== null && options.all === true;
  dnsLookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
    if (err) return callback(err, wantAll ? [] : "", undefined);
    if (!addresses.length || addresses.some((a) => !isPublicIp(a.address))) {
      const e = new Error(`Refusing to connect to non-public address for ${hostname}`) as NodeJS.ErrnoException;
      e.code = "ESSRFBLOCKED";
      return callback(e, wantAll ? [] : "", undefined);
    }
    if (wantAll) return callback(null, addresses);
    return callback(null, addresses[0].address, addresses[0].family);
  });
}
