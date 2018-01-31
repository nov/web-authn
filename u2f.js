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
      user: user
    }
  }).then(registered);
};

const registered = (attestation) => {
  attestation.rawId                      = __url_safe_b64_encode__(attestation.rawId);
  attestation.response.attestationObject = __url_safe_b64_encode__(attestation.response.attestationObject);
  attestation.response.clientDataJSON    = __url_safe_b64_encode__(attestation.response.clientDataJSON);
  console.log('Attestation', attestation);

  localStorage.setItem('key_id', attestation.id);
  setup();
};

const authenticate = () => {
  event.preventDefault();

  console.log('authenticate', {key_id: key_id.value});

  navigator.credentials.get({
    publicKey: {
      challenge: new TextEncoder().encode(challenge),
      rpId: location.host,
      allowCredentials: [{
        id: __url_safe_b64_decode__(key_id.value),
        type: 'public-key'
      }]
    }
  }).then(authenticated);
};

const authenticated = (assertion) => {
  assertion.rawId                      = __url_safe_b64_encode__(assertion.rawId);
  assertion.response.authenticatorData = __url_safe_b64_encode__(assertion.response.authenticatorData);
  assertion.response.clientDataJSON    = __url_safe_b64_encode__(assertion.response.clientDataJSON);
  assertion.response.signature         = __url_safe_b64_encode__(assertion.response.signature);
  assertion.response.userHandle        = __url_safe_b64_encode__(assertion.response.userHandle);

  console.log('Assertion', assertion);
  console.log('authenticatorData', __url_safe_b64_encode__(assertion.response.authenticatorData));
};

const setup = () => {
  key_id.value = localStorage.getItem('key_id');
};

const __url_safe_b64_encode__ = (array_buffer) => {
  let uint8_array = new Uint8Array(array_buffer).reduce(
    (s, byte) => s + String.fromCharCode(byte), ''
  );
  return btoa(uint8_array).replace(/_/g, '/').replace(/-/g, '+');
};

const __url_safe_b64_decode__ = (string) => {
  let byte_array = atob(string.replace(/_/g, '/').replace(/-/g, '+'));
  return Uint8Array.from(byte_array, c => c.charCodeAt(0));
}

registration.addEventListener('submit', register);
authentication.addEventListener('submit', authenticate);
setup();
