import type { Request, Response } from 'express';
import { ApiResponse } from '../utils/apiResponse.js';

/**
 * Middleware to handle 404 Not Found errors
 * This should be mounted after all other routes
 */
export const notFoundHandler = (req: Request, res: Response) => {
  if (req.path.startsWith('/api/')) {
    return ApiResponse.error(res, '🔍 Oops! Looks like you are lost. 🗺️', 404);
  }

  return res.status(404).render('pages/app/error', {
    title: 'Error · Authura',
    statusCode: 404,
    message: 'Oops! Looks like you are lost. Page not found',
    stack: undefined,
  });
};
