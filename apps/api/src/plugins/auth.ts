import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import { buildActor, type Actor } from '../actor.js';
import { csrfMatches, validateSession } from '../auth/session.js';
import { getConfig } from '../config.js';
import { forbidden, mfaRequired, unauthenticated } from '../errors.js';

declare module 'fastify' {
  interface FastifyRequest {
    /** Populated by `requireAuth`. Null on public routes. */
    actor: Actor | null;
  }
  interface FastifyInstance {
    /** preHandler: full authentication, including satisfied 2FA. */
    requireAuth: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    /**
     * preHandler for the narrow window between password and TOTP: a session
     * exists but authorises nothing except completing enrolment or verification.
     */
    requirePartialAuth: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function clientIp(request: FastifyRequest): string | null {
  // `trustProxy` is configured on the server, so request.ip already accounts
  // for X-Forwarded-For when we are behind a proxy we control.
  return request.ip || null;
}

function ipAllowed(ip: string | null, allowlist: string[]): boolean {
  if (allowlist.length === 0) return true;
  if (!ip) return false;

  return allowlist.some((entry) => {
    if (!entry.includes('/')) return entry === ip;

    // Minimal IPv4 CIDR check. Anything more exotic belongs at the network
    // edge, not in application code pretending to be a firewall.
    const [network, bitsRaw] = entry.split('/');
    const bits = Number(bitsRaw);
    if (!network || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;

    const toInt = (addr: string): number | null => {
      const parts = addr.split('.');
      if (parts.length !== 4) return null;
      let value = 0;
      for (const part of parts) {
        const octet = Number(part);
        if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
        value = (value << 8) | octet;
      }
      return value >>> 0;
    };

    const ipInt = toInt(ip);
    const netInt = toInt(network);
    if (ipInt === null || netInt === null) return false;

    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (ipInt & mask) === (netInt & mask);
  });
}

async function resolveActor(
  request: FastifyRequest,
  options: { requireMfa: boolean },
): Promise<Actor> {
  const config = getConfig();
  const ip = clientIp(request);

  if (!ipAllowed(ip, config.ipAllowlist)) {
    throw forbidden('This console is not reachable from your network.');
  }

  const token = request.cookies[config.cookieName];
  if (!token) throw unauthenticated();

  const session = await validateSession(token);
  if (!session) throw unauthenticated('Your session has expired. Sign in again.');

  if (options.requireMfa && !session.mfaSatisfied) {
    throw mfaRequired('Finish two-factor authentication to continue.');
  }

  // CSRF is checked only for state-changing verbs, and only once we know a
  // session exists — an unauthenticated POST should read as 401, not 403.
  if (MUTATING.has(request.method)) {
    const cookie = request.cookies[config.csrfCookieName];
    const header = request.headers['x-csrf-token'];
    const headerValue = Array.isArray(header) ? header[0] : header;
    if (!csrfMatches(cookie, headerValue)) {
      throw forbidden('Missing or invalid CSRF token. Reload the console and try again.');
    }
  }

  const actor = await buildActor(session.adminId, {
    sessionId: session.id,
    ip,
    userAgent: request.headers['user-agent'] ?? null,
    requestId: request.id,
  });

  if (!actor) throw unauthenticated();

  // A suspended admin's session is already excluded by validateSession's join,
  // but re-checking here closes the gap between that query and this one.
  if (!actor.active) {
    throw forbidden('Your admin account is not active. Contact the Super Admin.');
  }

  return actor;
}

export default fp(async function authPlugin(fastify: FastifyInstance) {
  fastify.decorateRequest('actor', null);

  fastify.decorate('requireAuth', async function requireAuth(request: FastifyRequest) {
    request.actor = await resolveActor(request, { requireMfa: true });
  });

  fastify.decorate('requirePartialAuth', async function requirePartialAuth(request: FastifyRequest) {
    request.actor = await resolveActor(request, { requireMfa: false });
  });
});

/** Narrowing helper so handlers do not repeat the null check. */
export function actorOf(request: FastifyRequest): Actor {
  if (!request.actor) {
    // Reaching here means a route was registered without requireAuth. That is a
    // programming error, and failing loudly is the whole point.
    throw unauthenticated();
  }
  return request.actor;
}
