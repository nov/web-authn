const cose_alg_ECDSA_w_SHA256 = -7;
const challenge = 'random-string-generated-by-rp-server';

const register = () => {
  let user = {
    id: new TextEncoder().encode(email.value),
    name: display_name.value,
    displayName: display_name.value
  };
  console.debug('register', user);

  navigator.credentials.create({
    publicKey: {
      challenge: new TextEncoder().encode(challenge),
      pubKeyCredParams: [{
        type: 'public-key',
        alg: cose_alg_ECDSA_w_SHA256
      }],
      rp: {
        id: 'nov.github.io',
        name: 'Nov Sample'
      },
      user: user
    }
  }).then(registered);

  return false;
};

const registered = (attestation) => {
  attestation.response.attestationObject = __b64_encode__(attestation.response.attestationObject);
  attestation.response.clientDataJSON    = __b64_encode__(attestation.response.clientDataJSON);
  console.debug(attestation);
  response = {}
  encoded.attestationObject
  console.debug(attestation.response.attestationObject)
  key_id.value = attestation.id;
};

const authenticate = () => {
  console.debug('authenticate', {key_id: key_id.value});
  return false;
};

const __b64_encode__ = (array_buffer) => {
  let uint8_array = new Uint8Array(array_buffer).reduce(
    (s, byte) => s + String.fromCharCode(byte), ''
  );
  return btoa(uint8_array);
};

registration.addEventListener('submit', register);
authentication.addEventListener('submit', authenticate);
