import { MailerService } from '@nestjs-modules/mailer';
import { HttpStatus, Injectable } from '@nestjs/common';
import { InviteTokensService } from 'src/invite-tokens/invite-tokens.service';
import { RedisService } from 'src/redis/redis.service';

@Injectable()
export class MailService {
    constructor(
        private readonly mailerService: MailerService,
        private readonly inviteTokensService: InviteTokensService,
        private readonly redisService: RedisService,
    ) {}

    private generateOtpCode(): string {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }

    async sendMailAsHtml(to: string, subject: string, html: string) {
        const mailOptions = {
            from: process.env.MAIL_FROM,
            to,
            subject,
            html: html,
        };

        const result = await this.mailerService.sendMail(mailOptions);

        return result;
    }

    async sendMailAsText(to: string, subject: string, text: string) {
        const mailOptions = {
            from: process.env.MAIL_FROM,
            to,
            subject,
            text,
        };

        const result = await this.mailerService.sendMail(mailOptions);

        return result;
    }

    async sendOtpCode(email: string) {
        const otpCode = this.generateOtpCode();
        const subject = 'Ваш код для входа';
        const key = `verification_code:${email}`;
        await this.redisService.del(key);
        await this.redisService.set(key, otpCode, 60);

        const htmlContent = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 5px; background-color: #f9f9f9;">
            <h2 style="color: #333;">Ваш код для подтверждения</h2>
            <p style="font-size: 16px; color: #555;">Здравствуйте!</p>
            <p style="font-size: 18px; font-weight: bold; color: #0084ff;">${otpCode}</p>
            <p style="font-size: 16px; color: #555;">Пожалуйста, введите этот код для подтверждения.</p>
            <p style="font-size: 14px; color: #777;">Обратите внимание: код действителен в течение 60 секунд.</p>
            <footer style="margin-top: 20px; font-size: 12px; color: #aaa;">
                <p>С уважением,<br>Ваша команда</p>
            </footer>
        </div>
    `;

        try {
            await this.redisService.get(key);

            await this.sendMailAsHtml(email, subject, htmlContent);

            return {
                message: 'OTP code sent successfully',
                code: HttpStatus.OK,
            };
        } catch (error) {
            return {
                message: 'Failed to send OTP code',
                code: HttpStatus.INTERNAL_SERVER_ERROR,
            };
        }
    }

    async sendInviteTokenAsHtml(email: string, token: string) {
        const subject = 'Приглашение в компанию';
        const link = `${process.env.LINK_INVITE}/invitation/${token}`;

        const htmlContent = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 5px; background-color: #f9f9f9;">
            <h2 style="color: #333;">Ваc приглашают в компанию</h2>
            <p style="font-size: 16px; color: #555;">Здравствуйте!</p>
            <p style="font-size: 18px; font-weight: bold; color: #0084ff;"><a>${link}</a></p>
            <p style="font-size: 16px; color: #555;">Пожалуйста, перейдите по ссылке что бы зарегистрироваться в компанию.</p>
            <p style="font-size: 14px; color: #777;">Обратите внимание: ссылка действительна 24 часа.</p>
            <footer style="margin-top: 20px; font-size: 12px; color: #aaa;">
                <p>С уважением,<br>Ваша команда</p>
            </footer>
        </div>
    `;

        await this.sendMailAsHtml(email, subject, htmlContent);
    }

    async sendInviteToken(email: string, organizationId: number) {
        const inviteToken = await this.inviteTokensService.getTokenByEmail(
            email,
            organizationId,
        );

        await this.sendInviteTokenAsHtml(email, inviteToken.token);
    }

    async sendUpdatedInviteToken(email: string, organizationId: number) {
        const inviteToken = await this.inviteTokensService.getTokenByEmail(
            email,
            organizationId,
        );
        const updatedInviteToken = await this.inviteTokensService.updateToken(
            inviteToken.id,
            organizationId,
        );

        await this.sendInviteTokenAsHtml(email, updatedInviteToken.token);
    }

    async createAndSendInviteToken(email: string, organizationId: number) {
        const inviteToken = await this.inviteTokensService.create(
            { email },
            organizationId,
        );

        await this.sendInviteTokenAsHtml(email, inviteToken.token);
    }
}
