import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  jsonSchemaTransform,
  serializerCompiler,
  validatorCompiler,
  type ZodTypeProvider,
} from 'fastify-type-provider-zod';

import { getConfig } from './config.js';
import { ApiError, isApiError } from './errors.js';
import authPlugin from './plugins/auth.js';
import adminRoutes from './routes/admins.js';
import auditRoutes from './routes/audit.js';
import authRoutes from './routes/auth.js';
import channelRoutes from './routes/channels.js';
import childSafetyRoutes from './routes/childsafety.js';
import enforcementRoutes from './routes/enforcement.js';
import healthRoutes from './routes/health.js';
import moderationRoutes from './routes/moderation.js';
import privacyRoutes from './routes/privacy.js';
import roleRoutes from './routes/roles.js';
import supportRoutes from './routes/support.js';
import userRoutes from './routes/users.js';

export async function buildApp(): Promise<FastifyInstance> {
  const config = getConfig();

  const app = Fastify({
    logger: {
      level: config.LOG_LEVEL,
      redact: {
        // Never let a credential reach the logs, including via an error dump.
        paths: [
          'req.headers.cookie',
          'req.headers.authorization',
          'req.headers["x-csrf-token"]',
          'req.body.password',
          'req.body.newPassword',
          'req.body.code',
          'req.body.recoveryCode',
        ],
        remove: true,
      },
    },
    // The console is expected to sit behind a reverse proxy on its own
    // hostname; without this, request.ip is the proxy and the IP allowlist and
    // audit log both record the wrong address.
    trustProxy: true,
    bodyLimit: 1_048_576,
    disableRequestLogging: false,
  }).withTypeProvider<ZodTypeProvider>();

  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        // The API serves JSON and the Swagger UI. No inline script beyond what
        // Swagger UI needs, and no remote origins at all.
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'", config.WEB_ORIGIN],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
      },
    },
    // Admin tooling should never be embedded anywhere.
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'no-referrer' },
    hsts: config.isProduction
      ? { maxAge: 31_536_000, includeSubDomains: true, preload: false }
      : false,
  });

  await app.register(cors, {
    origin: config.WEB_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
    allowedHeaders: ['content-type', 'x-csrf-token'],
    maxAge: 600,
  });

  await app.register(cookie, {
    secret: config.SESSION_SECRET,
    parseOptions: {
      httpOnly: true,
      sameSite: 'strict',
      secure: config.isProduction,
      path: '/',
    },
  });

  // Global floor. Individual routes tighten this — login especially.
  await app.register(rateLimit, {
    global: true,
    max: 300,
    timeWindow: '1 minute',
    keyGenerator: (request) => request.ip,
    errorResponseBuilder: () => ({
      error: { code: 'rate_limited', message: 'Too many requests. Slow down and try again.' },
    }),
  });

  await app.register(swagger, {
    openapi: {
      openapi: '3.1.0',
      info: {
        title: 'NeverOff Admin & Trust/Safety Console API',
        version: '0.1.0',
        description:
          'Administration API for the NeverOff messenger platform.\n\n' +
          'NOTE: NeverOff 1:1 and group messages are end-to-end encrypted. No endpoint ' +
          'in this API returns message content, and none can — the server does not hold ' +
          'the keys. Moderation of private messages is possible only from evidence a ' +
          'reporter voluntarily submits. Channel posts are stored in plaintext by design ' +
          'and are moderatable server-side.',
      },
      servers: [{ url: `http://${config.API_HOST}:${config.API_PORT}` }],
      tags: [
        { name: 'auth', description: 'Sign-in, 2FA, sessions' },
        { name: 'users', description: 'User directory and profiles' },
        { name: 'enforcement', description: 'The §3.3 action ladder and appeals' },
        { name: 'moderation', description: 'Report clustering, the case queue and decisions' },
        { name: 'channels', description: 'Channel directory and the §6.5 action ladder' },
        { name: 'support', description: '@support ticket inbox and agent tooling' },
        { name: 'admins', description: 'Admin accounts and delegation' },
        { name: 'roles', description: 'Roles and the permission matrix' },
        { name: 'audit', description: 'Immutable audit log' },
        { name: 'privacy', description: 'Consent, retention, data subject rights' },
        { name: 'child-safety', description: 'Isolated pipeline (§6.7) — scaffold only' },
      ],
    },
    transform: jsonSchemaTransform,
  });

  if (!config.isProduction) {
    await app.register(swaggerUi, { routePrefix: '/docs' });
  }

  await app.register(authPlugin);

  await app.register(healthRoutes);
  await app.register(authRoutes, { prefix: '/api/auth' });
  await app.register(userRoutes, { prefix: '/api/users' });
  await app.register(enforcementRoutes, { prefix: '/api/enforcement' });
  await app.register(moderationRoutes, { prefix: '/api/moderation' });
  await app.register(channelRoutes, { prefix: '/api/channels' });
  await app.register(supportRoutes, { prefix: '/api/support' });
  await app.register(adminRoutes, { prefix: '/api/admins' });
  await app.register(roleRoutes, { prefix: '/api/roles' });
  await app.register(auditRoutes, { prefix: '/api/audit' });
  await app.register(privacyRoutes, { prefix: '/api/privacy' });
  await app.register(childSafetyRoutes, { prefix: '/api/child-safety' });

  app.setErrorHandler((error, request, reply) => {
    if (isApiError(error)) {
      if (error.statusCode >= 500) {
        request.log.error({ err: error }, 'api error');
      } else {
        request.log.info(
          { code: error.code, path: request.url, actor: request.actor?.id },
          error.message,
        );
      }
      return reply.status(error.statusCode).send(error.toResponse());
    }

    // Zod validation failures arrive with a `validation` property.
    if ((error as { validation?: unknown }).validation) {
      return reply.status(422).send({
        error: {
          code: 'validation_failed',
          message: 'The request body did not validate.',
          details: { issues: (error as { validation: unknown }).validation },
        },
      });
    }

    // Postgres raise_exception from a guard trigger — surface the message,
    // since those are written to be read by an admin.
    const pgCode = (error as { code?: string }).code;
    if (pgCode === 'P0001') {
      return reply.status(409).send({
        error: { code: 'conflict', message: error.message },
      });
    }
    if (pgCode === '23505') {
      return reply.status(409).send({
        error: { code: 'conflict', message: 'That record already exists.' },
      });
    }

    request.log.error({ err: error }, 'unhandled error');
    return reply.status(500).send({
      error: {
        code: 'internal',
        message: config.isProduction
          ? 'Something went wrong. The incident has been logged.'
          : error.message,
      },
    });
  });

  app.setNotFoundHandler((request, reply) => {
    reply.status(404).send({
      error: { code: 'not_found', message: `No route for ${request.method} ${request.url}.` },
    });
  });

  return app as unknown as FastifyInstance;
}

export { ApiError };
