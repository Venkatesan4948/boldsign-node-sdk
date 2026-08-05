import axios from 'axios';
import * as querystring from 'querystring';
import { OAuthToken } from '../auth/OAuthToken';
import { PKCEHelper } from './PKCEHelper';

export enum Region {
    US = "https://account.boldsign.com",
    EU = "https://account-eu.boldsign.com",
    CA = "https://account-ca.boldsign.com"
}

interface OAuthClientConfig {
    clientId: string;
    clientSecret: string;
    scope?: string;
    redirectUri?: string;
    state?: string;
    region?: Region;
    codeChallenge?: string;
    codeVerifier?: string;
}

export class OAuthClient {
    static AUTH_URL = Region.US;
    static code_verifier: string;
    static code_challenge: string;

    clientId: string;
    clientSecret: string;
    redirectUri: string | null;
    scope: string|null;
    state: string | null;
    region: string | null;
    codeChallenge: string | null;
    codeVerifier: string | null;

    static {
        const pkce = PKCEHelper.generatePkceCodes();
        OAuthClient.code_verifier = pkce.codeVerifier;
        OAuthClient.code_challenge = pkce.codeChallenge;
    }
    

    constructor(config: OAuthClientConfig) {
        this.clientId = config.clientId;
        this.clientSecret = config.clientSecret;
        this.redirectUri = config.redirectUri ?? null;
        this.scope = config.scope ?? null;
        this.state = config.state ?? null;
        this.region = config.region?.valueOf() ?? null;
        this.codeChallenge = config.codeChallenge ?? null;
        this.codeVerifier = config.codeVerifier ?? null;
    }

    getAuthorizationURL(state: string|null = null): string {
        if (this.codeChallenge === null) {
            this.codeChallenge = OAuthClient.code_challenge;
        }

        const params = querystring.stringify({
            response_type: "code",
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            scope: this.scope,
            state: state || this.state,
            code_challenge: this.codeChallenge,
            code_challenge_method: "S256"
        });

        const region = this.region ?? OAuthClient.AUTH_URL.valueOf();
        return `${region}/connect/authorize?${params}`;
    }

    private _handleResponse(response: any): OAuthToken {
        if (response.data.error) {
            throw new Error(`OAuth Error: ${response.data.error}`);
        }
        return new OAuthToken(
            response.data.access_token,
            response.data.token_type,
            response.data.expires_in,
            response.data.refresh_token,
            response.data.scope
        );
    }

    async exchangeCodeForToken(code: string): Promise<OAuthToken> {
        if (this.codeVerifier === null) {
            this.codeVerifier = OAuthClient.code_verifier;
        }

        const payload = querystring.stringify({
            grant_type: 'authorization_code',
            client_id: this.clientId,
            client_secret: this.clientSecret,
            code: code,
            redirect_uri: this.redirectUri,
            code_verifier: this.codeVerifier
        });

        const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
        const region = this.region ?? OAuthClient.AUTH_URL.valueOf();
        const response = await axios.post(`${region}/connect/token`, payload, { headers });

        return this._handleResponse(response);
    }

    async refreshAccessToken(refreshToken: string): Promise<OAuthToken> {
        const payload = querystring.stringify({
            grant_type: 'refresh_token',
            client_id: this.clientId,
            client_secret: this.clientSecret,
            refresh_token: refreshToken
        });

        const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
        const region = this.region ?? OAuthClient.AUTH_URL.valueOf();
        const response = await axios.post(`${region}/connect/token`, payload, { headers });

        return this._handleResponse(response);
    }

    async getTokenWithClientCredentials(): Promise<OAuthToken> {
        const payload = querystring.stringify({
            grant_type: 'client_credentials',
            client_id: this.clientId,
            client_secret: this.clientSecret,
            scope: this.scope
        });

        const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
        const region = this.region ?? OAuthClient.AUTH_URL.valueOf();
        const response = await axios.post(`${region}/connect/token`, payload, { headers });

        return this._handleResponse(response);
    }
}