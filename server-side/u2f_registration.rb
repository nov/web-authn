require 'cbor'
require 'json/jwt'

def inspect_attestation_object(attestation_object)
  cbor_bytes = Base64.urlsafe_decode64 attestation_object
  cbor = CBOR.decode cbor_bytes

  p cbor, cbor.keys, cbor['attStmt'].keys

  puts
  if cbor['attStmt'].present?
    puts '# Attestation Statement Certificates'
    cbor['attStmt']['x5c'].each do |att_stmt_cert|
      cert = OpenSSL::X509::Certificate.new att_stmt_cert
      puts cert.to_pem, cert.to_text
    end
  end

  auth_data = cbor['authData']
  rp_id_hash,
  flags,
  sign_count,
  attestation_data = [
    auth_data.byteslice(0...32),
    auth_data.byteslice(32),
    auth_data.byteslice(33...37),
    auth_data.byteslice(37..-1)
  ]
  puts '# RPID Hash'
  puts Base64.urlsafe_encode64(rp_id_hash, padding: false)
  puts
  puts '# Flags'
  p flags
  puts
  puts '# Sign Count'
  p sign_count
  puts

  length = (
    ((attestation_data.getbyte(16) << 8) & 0xFF) +
    (attestation_data.getbyte(17) & 0xFF)
  )
  aaguid,
  credential_id,
  cbor_encoded_ec_key = [
    attestation_data.byteslice(0...16),
    attestation_data.byteslice(18...(18 + length)),
    attestation_data.byteslice((18 + length)..-1),
  ]
  puts '# AAGUID'
  p aaguid
  puts
  puts
  puts '# Credential ID'
  puts Base64.urlsafe_encode64(credential_id, padding: false)

  cbor_ec_key = CBOR.decode(cbor_encoded_ec_key)
  jwk = JSON::JWK.new(
    kty: :EC,
    crv: :'P-256',
    x: Base64.urlsafe_encode64(cbor_ec_key[-2], padding: false),
    y: Base64.urlsafe_encode64(cbor_ec_key[-3], padding: false),
  )

  puts
  puts '# Device Public Key (PEM)'
  puts jwk.to_key.to_pem
  puts
  puts '# Device Public Key (TEXT)'
  puts jwk.to_key.to_text
end

[
  'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEMsuA3KzDw1JGLLAfO_4wLebzcS8w_SDs0Zw7pbhYlJVBAAAAPgAAAAAAAAAAAAAAAAAAAAAAQBBQHzNjCIqpdkEa8go1a53-QxcfxDhyJZK-m6BPy4PHZlVlsmQ5jtxzSBt02WO_TqTmLrZV_P3_aqNxyBrojWqlAQIDJiABIVggCL9kKivDYlLKly11xF8Hf6F0vGWbLYMqTCx2FtnQOs0iWCD9NxFEzz5UFnyGEgT8AUNYQq5KtYA63MyZ9mWf4reOJw'
].each do |attestation_object|
  inspect_attestation_object(attestation_object)
end
