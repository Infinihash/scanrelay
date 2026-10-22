output "public_ip" {
  description = "Point the copier's SMTP server (or tls_hostname's A record) here; port 587, STARTTLS."
  value       = aws_eip.relay.public_ip
}

output "instance_id" {
  description = "Admin shell: aws ssm start-session --target <instance_id>"
  value       = aws_instance.relay.id
}

output "security_group_id" {
  value = aws_security_group.relay.id
}
