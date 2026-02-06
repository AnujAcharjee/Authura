import { ErrorRequestHandler } from 'express';
import { AppError } from '@/utils/appError';
import { ApiResponse } from '@/utils/apiResponse';
import { logger } from '@/config/logger';

/**
 * if req accepts html
 *  - for routes in AUTH_UI_REDIRECT_MAP, redirect to auth route with error message
 *  - for Others, render error page
 * if req accepts json
 *  - send JSON res
 */

const AUTH_UI_REDIRECT_MAP: Record<string, string> = {
  '/api/auth/signup': '/signup',
  '/api/auth/signin': '/signin',
  '/api/auth/reset-password': '/reset-password',
  '/api/auth/forgot-password': '/forgot-password',
  '/api/client': '/client',
};

export const errorMiddleware: ErrorRequestHandler = (err, req, res, _next): void => {
  const isAppError = err instanceof AppError;
  const statusCode = isAppError ? err.statusCode : 500;
  const message = isAppError ? err.message : 'Internal server error';

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

  const acceptsHtml = req.accepts(['html', 'json']) === 'html';

  // HTML response
  if (acceptsHtml) {
    const redirectTarget = AUTH_UI_REDIRECT_MAP[req.path];

    if (redirectTarget) {
      return res.redirect(`${redirectTarget}?error=${encodeURIComponent(message)}`);
    }

    return res.status(statusCode).render('pages/app/error', {
      title: 'Error · Authura',
      statusCode,
      message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    });
  }

  // JSON response
  return ApiResponse.error(res, message, statusCode);
};
