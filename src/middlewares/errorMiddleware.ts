import { ErrorRequestHandler } from 'express';
import { AppError } from '../utils/appError.js';
import { ApiResponse } from '../utils/apiResponse.js';
import { logger } from '../config/logger.js';

/**
 * if req accepts html
 *  - for routes in AUTH_UI_REDIRECT_MAP, redirect to auth route with error message
 *  - for Others, render error page
 * if req accepts json
 *  - send JSON res
 */

const UI_ERROR_REDIRECT_MAP: Record<string, string> = {
  '/auth/signup': '/signup',
  '/auth/signin': '/signin',
  '/auth/forgot-password': '/forgot-password',
  '/auth/reset-password': '/reset-password',
};

export const errorMiddleware: ErrorRequestHandler = (err, req, res, _next): void => {
  const isAppError = err instanceof AppError;
  const statusCode = isAppError ? err.statusCode : 500;
  const message = isAppError ? err.message : 'Internal server error';
  const isApiRoute = req.path.startsWith('/api/');
  const acceptsHtml = req.accepts(['html', 'json']) === 'html';
  const secFetchMode = req.get('sec-fetch-mode');
  const contentType = req.get('content-type') || '';
  const isBrowserNavigate = secFetchMode === 'navigate';
  const isFormSubmit =
    req.method !== 'GET' &&
    (contentType.includes('application/x-www-form-urlencoded') ||
      contentType.includes('multipart/form-data'));
  const shouldRedirectHtml = isApiRoute && acceptsHtml && isBrowserNavigate && isFormSubmit;

  // Logging
  if (!isAppError || statusCode >= 500) {
    logger.error({
      message: err.message,
      stack: err.stack,
      path: req.path,
      method: req.method,
    });
  } else {
    logger.warn({
      message: err.message,
      path: req.path,
      method: req.method,
      statusCode,
    });
  }

  // Browser form submits from API endpoints: redirect to UI with error.
  if (shouldRedirectHtml) {
    // Exact match
    if (UI_ERROR_REDIRECT_MAP[req.path]) {
      return res.redirect(303, `${UI_ERROR_REDIRECT_MAP[req.path]}?error=${encodeURIComponent(message)}`);
    }

    // Prefix match
    if (req.path.startsWith('/api/v1/account')) {
      return res.redirect(303, `${'/account'}?error=${encodeURIComponent(message)}`);
    }

    if (req.path.startsWith('/api/v1/client')) {
      const clientPathMatch = req.path.match(/^\/api\/v1\/client\/([^/]+)/);
      if (clientPathMatch) {
        const clientId = clientPathMatch[1];
        return res.redirect(303, `/client/${encodeURIComponent(clientId)}?error=${encodeURIComponent(message)}`);
      }

      return res.redirect(303, `/account?error=${encodeURIComponent(message)}`);
    }
  }

  // API response: always JSON unless the request matched redirect-safe form submit rules.
  if (isApiRoute) {
    return ApiResponse.error(res, message, statusCode);
  }

  // UI response
  if (acceptsHtml) {
    return res.status(statusCode).render('pages/app/error', {
      title: 'Error · Authura',
      statusCode,
      message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    });
  }

  // Fallback
  return ApiResponse.error(res, message, statusCode);
};
