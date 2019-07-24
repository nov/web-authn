require 'cbor'
require 'json/jwt'

def inspect_attestation_object(attestation_object)
  cbor_bytes = Base64.urlsafe_decode64 attestation_object
  cbor = CBOR.decode cbor_bytes

  p cbor, cbor.keys, cbor['attStmt'].keys

  if cbor['attStmt'].present?
    puts
    puts '# Attestation Statement Certificates'
    if cbor['attStmt']['x5c'].present?
      cbor['attStmt']['x5c'].each do |att_stmt_cert|
        cert = OpenSSL::X509::Certificate.new att_stmt_cert
        puts cert.to_pem, cert.to_text
      end
    elsif cbor['attStmt']['response'].present?
      jwt = JSON::JWT.decode cbor['attStmt']['response'], :skip_verification
      puts jwt.pretty_generate
    end
  end
  puts

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
  'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhANsy4jAv4_BLPmM1pua45Pqo1gfIMA3KDgG-22P0eSH1AiEA3vRxM21j1nKLYyWTdgigzjZHG81IU3JXt2hh0Hr-P_tjeDVjgVkCwjCCAr4wggGmoAMCAQICBHSG_cIwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG8xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDE5NTUwMDM4NDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASVXfOt9yR9MXXv_ZzE8xpOh4664YEJVmFQ-ziLLl9lJ79XQJqlgaUNCsUvGERcChNUihNTyKTlmnBOUjvATevto2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIFIDAhBgsrBgEEAYLlHAEBBAQSBBD4oBHzjApNFYAGFxEfntx9MAwGA1UdEwEB_wQCMAAwDQYJKoZIhvcNAQELBQADggEBADFcSIDmmlJ-OGaJvWn9CqhvSeueToVFQVVvqtALOgCKHdwB-Wx29mg2GpHiMsgQp5xjB0ybbnpG6x212FxESJ-GinZD0ipchi7APwPlhIvjgH16zVX44a4e4hOsc6tLIOP71SaMsHuHgCcdH0vg5d2sc006WJe9TXO6fzV-ogjJnYpNKQLmCXoAXE3JBNwKGBIOCvfQDPyWmiiG5bGxYfPty8Z3pnjX-1MDnM2hhr40ulMxlSNDnX_ZSnDyMGIbk8TOQmjTF02UO8auP8k3wt5D1rROIRU9-FCSX5WQYi68RuDrGMZB8P5-byoJqbKQdxn2LmE1oZAyohPAmLcoPO5oYXV0aERhdGFYxDLLgNysw8NSRiywHzv-MC3m83EvMP0g7NGcO6W4WJSVQQAAAAv4oBHzjApNFYAGFxEfntx9AEA02xXaLwowZrcHlY4sjukQfJOcMH6ulShKwJM5F4ScjEZHw5pzBzgX2Us_FsAqBP4D3f7rnJ3khIHK7bwY6vtYpQECAyYgASFYIJCdNP17MO609HucLCpQWeeCqIDtipNu2yK0PZHMPh1KIlggRfqxNbCUPKGPZn_NLUdXP2Jsf2ErcCoLEq9O7yEpZvQ',
].each do |attestation_object|
  inspect_attestation_object(attestation_object)
end
