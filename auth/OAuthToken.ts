export default class OAuthToken {
    accessToken: string;
    tokenType: string;
    expiresIn: number;
    refreshToken: string | null;
    scope: string;

    constructor(accessToken: string, tokenType: string, expiresIn: number, refreshToken: string | null, scope: string) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.refreshToken = refreshToken;
        this.scope = scope;
    }
}

export { OAuthToken };
