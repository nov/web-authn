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
  attestation.rawId                      = __b64_encode__(attestation.rawId);
  attestation.response.attestationObject = __b64_encode__(attestation.response.attestationObject);
  attestation.response.clientDataJSON    = __b64_encode__(attestation.response.clientDataJSON);
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
        id: Uint8Array.from(atob(key_id.value.replace(/_/g, '/').replace(/-/g, '+')), c => c.charCodeAt(0)),
        type: 'public-key'
      }]
    }
  }).then(authenticated);
};

const authenticated = (assertion) => {
  assertion.rawId                      = __b64_encode__(assertion.rawId);
  assertion.response.authenticatorData = __b64_encode__(assertion.response.authenticatorData);
  assertion.response.clientDataJSON    = __b64_encode__(assertion.response.clientDataJSON);
  assertion.response.signature         = __b64_encode__(assertion.response.signature);
  assertion.response.userHandle        = __b64_encode__(assertion.response.userHandle);

  console.log('Assertion', assertion);
};

const setup = () => {
  key_id.value = localStorage.getItem('key_id');
};

const __b64_encode__ = (array_buffer) => {
  let uint8_array = new Uint8Array(array_buffer).reduce(
    (s, byte) => s + String.fromCharCode(byte), ''
  );
  return btoa(uint8_array);
};

registration.addEventListener('submit', register);
authentication.addEventListener('submit', authenticate);
setup();
