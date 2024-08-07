export interface ActiveUserData {
    sub: number;

    email: string;

    roles: string[];

    banned: boolean;

    organizationId: number;
}
