require 'cbor'
require 'json/jwt'

def inspect_authenticator_data(authenticator_data)
  authenticator_data_bytes = UrlSafeBase64.decode64 authenticator_data
  # authenticator_data_bytes.each_byte.with_index do |b, i|
  #   puts "#{i} :: #{b}"
  # end
  rp_id_hash,
  flags,
  sign_count = [
    authenticator_data_bytes.byteslice(0...32),
    authenticator_data_bytes.byteslice(32),
    authenticator_data_bytes.byteslice(33..-1)
  ]
  p "rp_id_hash : #{rp_id_hash}"
  p "flags : #{flags}"
  p "sign_count : #{sign_count}"
end

[
  '7zy5R_qrIHH0M0xgtEGVdDMvK9j5NPuadvjrgbSVRsgBAAAAGQ',
  '7zy5R_qrIHH0M0xgtEGVdDMvK9j5NPuadvjrgbSVRsgBAAAAGg',
  '7zy5R_qrIHH0M0xgtEGVdDMvK9j5NPuadvjrgbSVRsgBAAAAGw'
].each do |authenticator_data|
  inspect_authenticator_data authenticator_data
end
