const cose_alg_ECDSA_w_SHA256 = -7;
const challenge = 'random-string-generated-by-rp-server';

const register = (event) => {
  event.preventDefault();

  let user = {
    id: new TextEncoder().encode(email.value),
    name: email.value,
    displayName: display_name.value
  };

  let user_verification_on_registration;
  if (user_verification_required_on_registration.checked) {
    user_verification_on_registration = 'required';
  } else if (user_verification_preferred_on_registration.checked) {
    user_verification_on_registration = 'preferred';
  } else if (user_verification_discouraged_on_registration.checked) {
    user_verification_on_registration = 'discouraged';
  }

  let authenticator_attachment;
  if (authenticator_attachment_platform_on_registration.checked) {
    authenticator_attachment = 'platform';
  } else if (authenticator_attachment_cross_platform_on_registration.checked) {
    authenticator_attachment = 'cross-platform';
  } else if (authenticator_attachment_not_specified_on_registration) {
    authenticator_attachment = null;
  }

  let authenticatorSelection = {
    requireResidentKey: require_resident_key.checked,
    userVerification: user_verification_on_registration
  };
  if (authenticator_attachment) {
    authenticatorSelection.authenticatorAttachment = authenticator_attachment;
  }

  let public_key_options = {
    challenge: new TextEncoder().encode(challenge),
    pubKeyCredParams: [{
      type: 'public-key',
      alg: cose_alg_ECDSA_w_SHA256
    }],
    rp: {
      id: location.host,
      name: 'Nov Sample'
    },
    authenticatorSelection: authenticatorSelection,
    user: user,
    // attestation: 'direct'
  };
  console.log('register', public_key_options);

  navigator.credentials.create({
    publicKey: public_key_options
  }).then(registered, error);
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
  console.log(
    'attestation.getClientExtensionResults()',
    attestation.getClientExtensionResults()
  );
};

const authenticate = (event) => {
  event.preventDefault();

  let user_verification_on_authentication;
  if (user_verification_required_on_authentication.checked) {
    user_verification_on_authentication = 'required';
  } else if (user_verification_preferred_on_authentication.checked) {
    user_verification_on_authentication = 'preferred';
  } else if (user_verification_discouraged_on_authentication.checked) {
    user_verification_on_authentication = 'discouraged';
  }

  let public_key_options = {
    challenge: new TextEncoder().encode(challenge),
    rpId: location.host,
    userVerification: user_verification_on_authentication
  };
  console.log('authenticate', public_key_options);

  navigator.credentials.get({
    publicKey: public_key_options
  }).then(authenticated, error);
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
  console.log(
    'assertion.getClientExtensionResults()',
    assertion.getClientExtensionResults()
  );
};

const error = (reason) => {
  console.log('error', reason);
};

const __url_safe_b64_encode__ = (buffer) => {
  return buffer.toString('base64')
    .replace(/\//g, '_')
    .replace(/\+/g, '-')
    .replace(/=/g, '');
};

const __url_safe_b64_decode__ = (string) => {
  let byte_array = atob(string.replace(/_/g, '/').replace(/-/g, '+'));
  return Uint8Array.from(byte_array, c => c.charCodeAt(0));
};

registration.addEventListener('submit', register);
authentication.addEventListener('submit', authenticate);
