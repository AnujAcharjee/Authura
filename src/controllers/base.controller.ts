import { Request, Response, NextFunction } from 'express';
import { ApiResponse } from '@/utils/apiResponse';

export abstract class BaseController {
  protected async handelRequest(
    req: Request,
    res: Response,
    next: NextFunction,
    action: () => Promise<any>,
    options?: { raw?: boolean },
  ): Promise<void> {
    try {
      const result = await action();

      if (options?.raw === true) {
        res.json(result);
        return;
      }

      ApiResponse.success(res, result?.data, result?.message);
    } catch (error) {
      next(error);
    }
  }
}
