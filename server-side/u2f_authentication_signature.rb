require 'json/jwt'

authenticator_data = 'MsuA3KzDw1JGLLAfO_4wLebzcS8w_SDs0Zw7pbhYlJUBAAAAOw'
client_data_json = 'eyJjaGFsbGVuZ2UiOiJjbUZ1Wkc5dExYTjBjbWx1WnkxblpXNWxjbUYwWldRdFlua3RjbkF0YzJWeWRtVnkiLCJvcmlnaW4iOiJodHRwczovL3dlYi1hdXRobi5zZWxmLWlzc3VlZC5hcHAiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0'
signature = 'MEUCIQDXp8Wqzz3ZYV7avKvH3R3XQhW7xPYb5Cq2nx3gpflDGwIgPN0tSy2mmgpI06IIKmjrIUxCvL4Rfc53mFXfVd_yL58'
public_key_pem = <<-PEM
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMpNU/8TjYoyN8FlhZ+YsOMAvyfQ4
i6/JN0/DPXuZMoxLvdb1vjh7vPUt2Osw3Bq+0NZsx3U/8kmpFuwsZhTi9A==
-----END PUBLIC KEY-----
PEM

signature_base_string = [
  Base64.urlsafe_decode64(authenticator_data),
  OpenSSL::Digest::SHA256.digest(Base64.urlsafe_decode64 client_data_json)
].join
public_key = OpenSSL::PKey::EC.new public_key_pem
result = public_key.dsa_verify_asn1(
  OpenSSL::Digest::SHA256.digest(signature_base_string),
  Base64.urlsafe_decode64(signature)
)

p result
