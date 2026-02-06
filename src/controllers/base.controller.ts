import type { Request, Response, NextFunction } from 'express';
import { ApiResponse } from '@/utils/apiResponse';
import { AppError } from '@/utils/appError';
import { ErrorCode } from '@/utils/errorCodes';

type ActionResult = {
  data?: unknown;
  message: string;
  successRedirect?: string;
  query?: string;
};

type HandleOptions = {
  raw?: boolean;
};

/**
 * if controller handles the response itself -> return
 * if req accepts html res -> redirect to render html route
 * if req accepts json -> return json
 */

export abstract class BaseController {
  protected async handleRequest(
    req: Request,
    res: Response,
    next: NextFunction,
    action: () => Promise<ActionResult | void>,
    options: HandleOptions = {},
  ): Promise<void> {
    try {
      const result = await action();

      // handled
      if (options.raw === true) {
        return;
      }

      // html
      if (req.accepts(['html', 'json']) === 'html') {
        if (!result?.successRedirect) {
          throw new AppError(
            'Missing successRedirect for HTML response',
            500,
            ErrorCode.INTERNAL_SERVER_ERROR,
            false,
          );
        }

        return res.redirect(
          `${result.successRedirect}?success=${encodeURIComponent(result.message)}${result.query ?? ''}`,
        );
      }

      // JSON
      ApiResponse.success(res, result?.data, result?.message);
    } catch (error) {
      next(error);
    }
  }
}
