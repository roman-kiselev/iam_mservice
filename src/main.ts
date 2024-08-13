import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as cookieParser from 'cookie-parser';
import { AppModule } from './app.module';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    const PORT = process.env.PORT || 7777;
    app.enableCors({
        origin: `${process.env.LINK_ORIGIN}`,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Укажите необходимые методы
        allowedHeaders: ['Content-Type', 'Authorization'], // Укажите допустимые заголовки
        credentials: true,
    });
    app.use(cookieParser());

    app.connectMicroservice<MicroserviceOptions>({
        transport: Transport.RMQ,
        options: {
            urls: [`${process.env.RABBIT_LINK}`],
            queue: 'iam_queue',
            queueOptions: {
                durable: true,
            },
        },
    });

    const config = new DocumentBuilder()
        .setTitle('IAM')
        .setDescription('IAM Api')
        .setVersion('1.0')
        .addTag('IAM')
        .addBearerAuth()
        .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('/api/docs', app, document);

    app.useGlobalPipes(
        new ValidationPipe({
            disableErrorMessages: false,
            whitelist: true,
            transform: true,
        }),
    );
    await app.startAllMicroservices();
    await app.listen(PORT);
}
bootstrap();
