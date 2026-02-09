import type { Request, Response } from 'express';
import { ApiResponse } from '../utils/apiResponse.js';

/**
 * Middleware to handle 404 Not Found errors
 * This should be mounted after all other routes
 */
export const notFoundHandler = (req: Request, res: Response) => {
  ApiResponse.error(res, '🔍 Oops! Looks like you are lost. 🗺️', 404);
}; 