import { Request, Response, NextFunction } from 'express';
import { ZodType, ZodError, prettifyError } from 'zod';
import { ValidationError } from '@/utils/errorHandler';

export const validateRequest = (schema: ZodType) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      schema.parse({
        body: req.body,
        query: req.query,
        params: req.params,
        headers: req.headers,
      });
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        next(new ValidationError(prettifyError(error) || 'Validation failed'));
        return;
      }

      next(new ValidationError('Invalid request data'));
    }
  };
};
