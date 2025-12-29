import { ErrorRequestHandler } from "express";
import { AppError } from "@/utils/appError";
import { ApiResponse } from "@/utils/apiResponse";
import { logger } from "@/config/logger";

export const errorMiddleware: ErrorRequestHandler = (
  error,
  _req,
  res,
  _next
): void => {
  logger.error({
    message: error.message,
    stack: error.stack,
    context: "ErrorHandler",
  });

  if (error instanceof AppError) {
    ApiResponse.error(res, error.message, error.statusCode);
    return;
  }

  ApiResponse.error(res, "Internal server error", 500);
};