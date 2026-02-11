import helmet from 'helmet';
import { Express } from 'express';
import { ENV } from '../config/env.js';

export const setupSecurityHeaders = (app: Express) => {
  // Hide Express fingerprint (reduce attack surface)
  app.disable('x-powered-by');

  app.use(
    helmet({
      /* -------- Content Security Policy -------- */
      
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"], // block all external resources by default

          scriptSrc: ["'self'"], // prevent remote script injection
          styleSrc: ["'self'", "'unsafe-inline'"], // required for SSR auth pages
          imgSrc: ["'self'", 'data:', 'https:'], // allow avatars, logos, QR codes
          fontSrc: ["'self'", 'https:', 'data:'], // allow embedded web fonts

          connectSrc: ["'self'"], // restrict XHR / fetch / OAuth calls

          objectSrc: ["'none'"], // block Flash, plugins, embeds

          frameAncestors: ["'none'"], // prevent clickjacking
          formAction: ["'self'"], // prevent form submission hijacking
          baseUri: ["'self'"],
          scriptSrcAttr: ["'none'"],

          ...(ENV.NODE_ENV === 'production' ?
            { upgradeInsecureRequests: [] } // force HTTPS in production
          : {}),
        },
      },

      /* -------- Cross-origin isolation -------- */

      crossOriginEmbedderPolicy: false, // required for OAuth redirects & Swagger
      crossOriginOpenerPolicy: { policy: 'same-origin' }, // isolate browsing context
      crossOriginResourcePolicy: { policy: 'same-origin' }, // block cross-origin loads

      /* -------- Other protections -------- */

      dnsPrefetchControl: { allow: false }, // prevent DNS leakage
      originAgentCluster: true, // isolate origin memory
      permittedCrossDomainPolicies: { permittedPolicies: 'none' }, // block Adobe policies
    }),
  );
};
