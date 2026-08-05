import * as crypto from "crypto";
import { DocumentEvent, IdentityVerificationEvent, SenderIdentityEvent, TemplateEvent, WebhookEvent } from "./model";

export class BoldSignSignatureException extends Error {}

export class WebhookUtility {
    public static readonly BOLD_SIGN_EVENT_HEADER = "X-BoldSign-Event";
    public static readonly BOLD_SIGN_SIGNATURE_HEADER = "X-BoldSign-Signature";
    public static readonly DEFAULT_TIME_TOLERANCE = 300;

    /**
     * Parses the raw JSON payload into a WebhookEvent object.
     * @param jsonPayload The raw JSON string from the webhook request.
     * @returns A WebhookEvent object.
     */
    public static parseEvent(
        jsonPayload: string,
    ): WebhookEvent {
        const raw = JSON.parse(jsonPayload);
        const webhookEvent = raw as WebhookEvent;

        this.resolveEventData(webhookEvent);
        return webhookEvent;

    }

    /**
     * Resolves webhook data into one of the concrete event models
     */
    private static resolveEventData(webhookEvent: WebhookEvent): void {
        const data: any = webhookEvent.data;
        if (!data || typeof data !== "object") {
            return;
        }

        if (data.object) {
            switch (data.object) {
                case "document":
                    webhookEvent.data = Object.assign(
                        new DocumentEvent(),
                        data
                    );
                    return;

                case "template":
                    webhookEvent.data = Object.assign(
                        new TemplateEvent(),
                        data
                    );
                    return;
                case "senderIdentity":
                    webhookEvent.data = Object.assign(
                        new SenderIdentityEvent(),
                        data
                    );
                    return;

                case "identityVerification":
                    webhookEvent.data = Object.assign(
                        new IdentityVerificationEvent(),
                        data
                    );
                    return;
            }
        }
    }


    public static validateSignature(
        jsonPayload: string,
        signatureHeader: string,
        secretKey: string,
        tolerance: number = WebhookUtility.DEFAULT_TIME_TOLERANCE
    ): void {
        const signatures = this.parseSignatureHeader(signatureHeader);

        const timestamp = signatures.t?.[0];
        if (!timestamp) {
            throw new BoldSignSignatureException("Timestamp not found");
        }

        const expectedSignature = this.generateSignature(
            secretKey,
            jsonPayload,
            timestamp
        );

        if (
            !this.isSignatureMatched(expectedSignature, signatures.s0) &&
            !this.isSignatureMatched(expectedSignature, signatures.s1)
        ) {
            throw new BoldSignSignatureException("Signature mismatch");
        }

        const ts = parseInt(timestamp, 10);
        const now = Math.floor(Date.now() / 1000);

        if (Math.abs(now - ts) > tolerance) {
            throw new BoldSignSignatureException("Timestamp out of tolerance");
        }
    }

    private static parseSignatureHeader(
        header: string
    ): Record<string, string[]> {
        const result: Record<string, string[]> = {};

        for (const part of header.split(",")) {
            const [key, value] = part.trim().split("=", 2);
            if (!key || !value) {
                throw new BoldSignSignatureException("Invalid signature header");
            }
            result[key] ??= [];
            result[key].push(value);
        }

        return result;
    }

    private static generateSignature(
        secret: string,
        payload: string,
        timestamp: string
    ): string {
        return crypto
            .createHmac("sha256", secret)
            .update(`${timestamp}.${payload}`)
            .digest("hex")
            .toLowerCase();
    }

    private static isSignatureMatched(
        signature: string,
        signatures?: string[]
    ): boolean {
        if (!signatures) return false;

        return signatures.some(sig =>
            crypto.timingSafeEqual(
                Buffer.from(sig.toLowerCase()),
                Buffer.from(signature)
            )
        );
    }
}