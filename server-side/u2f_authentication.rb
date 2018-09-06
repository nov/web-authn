require 'cbor'
require 'json/jwt'

def inspect_authenticator_data(authenticator_data)
  authenticator_data_bytes = Base64.urlsafe_decode64 authenticator_data
  # authenticator_data_bytes.each_byte.with_index do |b, i|
  #   puts "#{i} :: #{b}"
  # end
  rp_id_hash,
  flags,
  sign_count = [
    authenticator_data_bytes.byteslice(0...32),
    authenticator_data_bytes.byteslice(32),
    authenticator_data_bytes.byteslice(33...37)
  ]
  puts '# RPID Hash'
  puts Base64.urlsafe_encode64(rp_id_hash, padding: false)
  puts
  puts '# Flags'
  p flags
  puts
  puts '# Sign Count'
  p sign_count
end

[
  'MsuA3KzDw1JGLLAfO_4wLebzcS8w_SDs0Zw7pbhYlJUEAAAAAQ'
].each do |authenticator_data|
  inspect_authenticator_data authenticator_data
end
