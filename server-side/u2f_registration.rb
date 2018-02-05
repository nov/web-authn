require 'cbor'
require 'json/jwt'

def inspect_attestation_object(attestation_object)
  cbor_bytes = UrlSafeBase64.decode64 attestation_object
  cbor = CBOR.decode cbor_bytes

  puts
  puts '# Attestation Statement Certificates'
  cbor['attStmt']['x5c'].each do |att_stmt_cert|
    cert = OpenSSL::X509::Certificate.new att_stmt_cert
    puts cert.to_pem, cert.to_text
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

  cbor_ec_key = CBOR.decode(cbor_encoded_ec_key)
  jwk = JSON::JWK.new(
    kty: :EC,
    crv: :'P-256',
    x: UrlSafeBase64.encode64(cbor_ec_key[-2]),
    y: UrlSafeBase64.encode64(cbor_ec_key[-3]),
  )

  puts
  puts '# Device Public Key'
  puts jwk.to_key.to_pem
end

[
  'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAPXV37xq1egrT2MZ3mWQ_OUV_y1IMOODGFOQOWomdSNmAiEAthEZovPtf_Fk9xyhvaEBq_ZV_TUeAmFp9nDIuxgp8q9jeDVjgVkCIDCCAhwwggEGoAMCAQICBCTbq0AwCwYJKoZIhvcNAQELMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjArMSkwJwYDVQQDDCBZdWJpY28gVTJGIEVFIFNlcmlhbCAxMzUwMzI3Nzg4ODBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAKwlL40fUd5QcR3jr7Fyk3tKkefqh5v7Dmv694MIHDLW9S9aclqeOO_h1H-tXkbjfrKwpQBdRyxV7l8CeQ5GjajEjAQMA4GCisGAQQBgsQKAQEEADALBgkqhkiG9w0BAQsDggEBAKNjrg6YOvMLuvEsiy3zWlm_HLtKGw_LaMSEVYSQ9oc0WGW42wJpw0blU4hMLFYHrw6ie5CsjPHvQx9yrBidshyCSRS_F4ilURoz0HtMjjRkfOn2HhUWqamzbpAKQCBh9pqkbhLFMrmT-UI--qpM-aO2VLTd3vKSSlSP1ZmVUQ3U9_TZpNUhk4c8ccm4foaFPp4tp16PDG0oMFN01O_dXhSW-MM5BhB71ovWNQ2q0sN4EeyjykO8kwtzQJfe9p1ojZRVDEz7GKniS4ai5diPSZiZoJvOW4EMU2yvOQ3Ivd6WDfMwysq8BSGhgyOVf_68pZypCyCxDQm1IxxYwn66Z4NoYXV0aERhdGFYxO88uUf6qyBx9DNMYLRBlXQzLyvY-TT7mnb464G0lUbIQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEDkf4lbmkKxFD0IIPzHXSG6qJhAI8OY-bnfz1qaM7rfMPMeBpxpbr5oM8TPMFWGuHADZX9SZdWqcvMp2Y6E8tglpQECAyYgASFYINKPW4-OE44QQ_srYfdUhzjTFQDdxYpSvvDP9yPer_wZIlgg71_IZieYVglM55Mu4KPLfL1_mtKGKeJEXKb0HwerAA8',
  'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgW6E-kYAfJoj2glzVN49zJ-gkVhg6JfTFsfV-LUHoOmUCIQCKxFQqhvXyXkTWB1UYTP7puozXwyM70vuEEHNvrmv4v2N4NWOBWQIgMIICHDCCAQagAwIBAgIEJNurQDALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCsxKTAnBgNVBAMMIFl1YmljbyBVMkYgRUUgU2VyaWFsIDEzNTAzMjc3ODg4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEArCUvjR9R3lBxHeOvsXKTe0qR5-qHm_sOa_r3gwgcMtb1L1pyWp447-HUf61eRuN-srClAF1HLFXuXwJ5DkaNqMSMBAwDgYKKwYBBAGCxAoBAQQAMAsGCSqGSIb3DQEBCwOCAQEAo2OuDpg68wu68SyLLfNaWb8cu0obD8toxIRVhJD2hzRYZbjbAmnDRuVTiEwsVgevDqJ7kKyM8e9DH3KsGJ2yHIJJFL8XiKVRGjPQe0yONGR86fYeFRapqbNukApAIGH2mqRuEsUyuZP5Qj76qkz5o7ZUtN3e8pJKVI_VmZVRDdT39Nmk1SGThzxxybh-hoU-ni2nXo8MbSgwU3TU791eFJb4wzkGEHvWi9Y1DarSw3gR7KPKQ7yTC3NAl972nWiNlFUMTPsYqeJLhqLl2I9JmJmgm85bgQxTbK85Dci93pYN8zDKyrwFIaGDI5V__rylnKkLILENCbUjHFjCfrpng2hhdXRoRGF0YVjE7zy5R_qrIHH0M0xgtEGVdDMvK9j5NPuadvjrgbSVRshBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQLH62jyfXBj-oCB8hb-GtyrL80Kva8-QFz8-9yvKHtmzfzboh_9vejdNGARngHGVjaz944G4totQC3WsZ-xjqrelAQIDJiABIVgg8FLzmGF1V1f1bn2ceCoqAv1GSodDm--HTRqH6Or5QvUiWCCPQr7pToV7b4R_Bj9KUjLkcBEBAEeETPPumHfI99nr1A'
].each do |attestation_object|
  inspect_attestation_object(attestation_object)
end
