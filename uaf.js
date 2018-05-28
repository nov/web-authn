const cose_alg_ECDSA_w_SHA256 = -7;
const challenge = 'random-string-generated-by-rp-server';

const register = (event) => {
  event.preventDefault();

  let user = {
    id: new TextEncoder().encode(email.value),
    name: email.value,
    displayName: display_name.value
  };
  console.log('register', user);

  navigator.credentials.create({
    publicKey: {
      challenge: new TextEncoder().encode(challenge),
      pubKeyCredParams: [{
        type: 'public-key',
        alg: cose_alg_ECDSA_w_SHA256
      }],
      rp: {
        id: location.host,
        name: 'Nov Sample'
      },
      user: user,
      attestation: 'direct'
    }
  }).then(registered);
};

const registered = (attestation) => {
  console.log('Attestation', attestation);
  console.log(
    'attestation.rawId',
    __url_safe_b64_encode__(attestation.rawId)
  );
  console.log(
    'attestation.response.attestationObject',
    __url_safe_b64_encode__(attestation.response.attestationObject)
  );
  console.log(
    'attestation.response.clientDataJSON',
    __url_safe_b64_encode__(attestation.response.clientDataJSON)
  );
};

const authenticate = (event) => {
  event.preventDefault();

  console.log('authenticate');

  navigator.credentials.get({
    publicKey: {
      challenge: new TextEncoder().encode(challenge),
      rpId: location.host
    }
  }).then(authenticated);
};

const authenticated = (assertion) => {
  console.log('Assertion', assertion);
  console.log(
    'assertion.rawId',
    __url_safe_b64_encode__(assertion.rawId)
  );
  console.log(
    'assertion.response.authenticatorData',
    __url_safe_b64_encode__(assertion.response.authenticatorData)
  );
  console.log(
    'assertion.response.clientDataJSON',
    __url_safe_b64_encode__(assertion.response.clientDataJSON)
  );
  console.log(
    'assertion.response.signature',
    __url_safe_b64_encode__(assertion.response.signature)
  );
  console.log(
    'assertion.response.userHandle',
    __url_safe_b64_encode__(assertion.response.userHandle)
  );
};

const __url_safe_b64_encode__ = (array_buffer) => {
  let uint8_array = new Uint8Array(array_buffer).reduce(
    (s, byte) => s + String.fromCharCode(byte), ''
  );
  return btoa(uint8_array).replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, '');
};

const __url_safe_b64_decode__ = (string) => {
  let byte_array = atob(string.replace(/_/g, '/').replace(/-/g, '+'));
  return Uint8Array.from(byte_array, c => c.charCodeAt(0));
};

registration.addEventListener('submit', register);
authentication.addEventListener('submit', authenticate);
