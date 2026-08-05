import * as crypto from 'crypto';

class PKCEHelper {
    /**
     * Utility class for generating PKCE (Proof Key for Code Exchange) codes.
     *
     * This generates:
     * - A `code_verifier`: A high-entropy cryptographic random string.
     * - A `code_challenge`: A SHA-256 hash of the `code_verifier`, encoded in a URL-safe format.
     *
     * These values are used in OAuth2 authentication flows to enhance security.
     */

    static generatePkceCodes() {
        try {
            // Generate a secure random code_verifier (32-byte base64 URL-safe string)
            const codeVerifier = crypto.randomBytes(32).toString('base64url');

            // Generate the corresponding code_challenge (SHA-256 hash of code_verifier)
            const codeChallenge = crypto.createHash('sha256')
                .update(codeVerifier)
                .digest('base64url');

            return { codeVerifier, codeChallenge };
        } catch (error) {
             if (error instanceof Error) {
                throw new Error(`PKCE generation failed: ${error.message}`);
            } else {
                throw new Error('PKCE generation failed due to an unknown error.');
            }
        }
    }
}

export { PKCEHelper };

