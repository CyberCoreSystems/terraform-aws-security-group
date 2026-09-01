output "security_group_id" {
  description = "ID of the security group."
  value       = aws_security_group.this.id
}

output "security_group_arn" {
  description = "ARN of the security group."
  value       = aws_security_group.this.arn
}

output "security_group_name" {
  description = "Actual name of the security group (includes the random suffix when use_name_prefix = true)."
  value       = aws_security_group.this.name
}

output "ingress_rule_ids" {
  description = "Map of rule index => ingress security group rule ID."
  value       = { for k, r in aws_vpc_security_group_ingress_rule.this : k => r.security_group_rule_id }
}

output "egress_rule_ids" {
  description = "Map of rule index => egress security group rule ID (custom rules only)."
  value       = { for k, r in aws_vpc_security_group_egress_rule.this : k => r.security_group_rule_id }
}

output "allow_all_egress_rule_ids" {
  description = "IDs of the allow-all IPv4/IPv6 egress rules (empty when allow_all_egress = false)."
  value = concat(
    aws_vpc_security_group_egress_rule.all_ipv4[*].security_group_rule_id,
    aws_vpc_security_group_egress_rule.all_ipv6[*].security_group_rule_id,
  )
}
