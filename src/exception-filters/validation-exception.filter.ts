import {
    ArgumentsHost,
    BadRequestException,
    Catch,
    ExceptionFilter,
    Logger,
} from '@nestjs/common';

@Catch(BadRequestException)
export class ValidationExceptionFilter implements ExceptionFilter {
    private readonly logger = new Logger(ValidationExceptionFilter.name);

    catch(exception: BadRequestException, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse();
        const request = ctx.getRequest();

        const status = exception.getStatus();
        //const errors = exception.getResponse() as ValidationError[];
        this.logger.error(`Validation error: ${JSON.stringify(exception)}`);

        response.status(status).json({
            statusCode: status,
            timestamp: new Date().toISOString(),
            path: request.url,
            message: exception,
        });
    }
}
