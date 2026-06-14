output "instance_id" {
  value = aws_instance.sentinel.id
}

output "public_ip" {
  value = aws_eip.main.public_ip
}

output "public_dns" {
  value = aws_eip.main.public_dns
}

output "key_name" {
  value = local.key_pair_name
}

output "key_private_key_pem" {
  value     = var.key_name == "" ? tls_private_key.main[0].private_key_pem : null
  sensitive = true
}

output "api_key" {
  value     = random_password.api_key.result
  sensitive = true
}
