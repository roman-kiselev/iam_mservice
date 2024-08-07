import {
    ArgumentsHost,
    Catch,
    ExceptionFilter,
    HttpException,
    Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
    logger = new Logger();
    constructor() {}

    catch(exception: HttpException, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse<Response>();
        const request = ctx.getRequest<Request>();

        const status = exception.getStatus();
        const errorDetails = exception.getResponse();
        this.logger.error(
            `${request.method} ${request.originalUrl} ${status} - ${exception.message} - ${JSON.stringify(errorDetails)}`,
        );

        response.status(status).json({ error: true, errorDetails });
    }
}
