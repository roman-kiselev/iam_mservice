import { Injectable, Logger, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
    logger = new Logger('Response');
    constructor() {}

    use(req: Request, res: Response, next: NextFunction) {
        const reqTime = new Date().getTime();

        req.on('close', () => {
            this.logRequest(req, res, reqTime);
        });

        res.on('finish', () => {
            this.logResponseFinish(req, res, reqTime);
        });

        next();
    }

    private logRequest(req: Request, res: Response, reqTime: number) {
        const { method, url, body, params, query, cookies } = req;
        const { statusCode: resStatusCode } = res;
        const log = `${method} ${url} StatusCode-${resStatusCode} ${new Date().getTime() - reqTime}ms Params-${JSON.stringify(params)} Query-${JSON.stringify(query)} Body-${JSON.stringify(body)} Cookies-${JSON.stringify(cookies)}`;

        if (resStatusCode < 400) {
            this.logger.log(log);
        }
    }

    private logResponseFinish(req: Request, res: Response, reqTime: number) {
        const { method, url } = req;
        const { statusCode } = res;
        const resTime = new Date().getTime();

        if (statusCode === 201 || statusCode === 200) {
            this.logger.log(
                `${method} ${url} StatusCode-${statusCode} - ${resTime - reqTime}ms`,
            );
        }
    }
}
