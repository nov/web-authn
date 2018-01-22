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
        type: 'public-key',
        id: Uint8Array.from(atob(key_id.value), c => c.charCodeAt(0))
      }]
    }
  }).then(registered);
};

const authenticated = (assertion) => {
  console.log('Assertion', assertion);
};

const setup = () => {
  key_id.value = localStorage.getItem('key_id');
};

registration.addEventListener('submit', register);
authentication.addEventListener('submit', authenticate);
setup();