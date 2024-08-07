export class TimeHelper {
    constructor() {}

    // Возвращает текущее время в формате ISO
    getCurrentTime(): string {
        return new Date().toISOString();
    }

    // Прибавляем 24 часа к текущему времени и возвращаем
    getExpiresAt(): string {
        const now = Date.now(); // Текущее время в миллисекундах
        const expiresAt = new Date(now + 24 * 60 * 60 * 1000); // Прибавляем 24 часа
        return expiresAt.toISOString();
    }

    // Сравниваем даты и проверяем, не просрочено ли время
    isExpired(expiresAt: string): boolean {
        return new Date(expiresAt) < new Date(); // Сравниваем с текущим временем
    }
}
