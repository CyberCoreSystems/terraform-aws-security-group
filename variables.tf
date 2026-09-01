variable "name" {
  description = "Name of the security group (also used as the Name tag)."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9._:/()#,@\\[\\]+=&;{}!$*-]{1,200}$", var.name)) && !startswith(var.name, "sg-")
    error_message = "name must be 1-200 valid security-group-name characters and must not start with \"sg-\"."
  }
}

variable "description" {
  description = "Description of the security group. Changing it forces replacement -- create_before_destroy is enabled so replacement is safe."
  type        = string
  default     = "Managed by Terraform (IaC Bazaar)"
}

variable "vpc_id" {
  description = "ID of the VPC the security group lives in."
  type        = string

  validation {
    condition     = can(regex("^vpc-", var.vpc_id))
    error_message = "vpc_id must be a VPC ID (vpc-...)."
  }
}

variable "use_name_prefix" {
  description = "Use name as a name_prefix (random suffix appended). Keeps create_before_destroy replacements collision-free; disable only if you need the exact name."
  type        = bool
  default     = true
}

variable "ingress_rules" {
  description = <<-EOT
    Ingress rules. Each rule names a preset (https, postgres, redis, ...) OR
    sets from_port/to_port/ip_protocol explicitly, plus exactly ONE source:
    cidr_ipv4, cidr_ipv6, prefix_list_id, referenced_security_group_id, or
    self = true (the group itself).
  EOT
  type = list(object({
    preset                       = optional(string)
    description                  = optional(string)
    from_port                    = optional(number)
    to_port                      = optional(number)
    ip_protocol                  = optional(string)
    cidr_ipv4                    = optional(string)
    cidr_ipv6                    = optional(string)
    prefix_list_id               = optional(string)
    referenced_security_group_id = optional(string)
    self                         = optional(bool, false)
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.ingress_rules :
      r.preset == null ? true : contains([
        "ssh", "http", "https", "http-alt", "https-alt", "dns-tcp", "dns-udp",
        "ntp", "smtp-tls", "ldap", "ldaps", "nfs", "postgres", "mysql", "mssql",
        "oracle-db", "redis", "memcached", "mongodb", "rabbitmq", "kafka",
        "elasticsearch", "prometheus", "node-exporter", "grafana",
        "kubernetes-api", "rdp", "winrm-http", "winrm-https", "all-icmp",
        "all-traffic",
      ], r.preset)
    ])
    error_message = "Unknown ingress preset. See the presets table in the README for valid names."
  }

  validation {
    condition = alltrue([
      for r in var.ingress_rules :
      r.preset != null || r.ip_protocol != null
    ])
    error_message = "Ingress rules without a preset must set ip_protocol (and from_port/to_port for tcp/udp)."
  }

  validation {
    condition = alltrue([
      for r in var.ingress_rules :
      length(compact([
        r.cidr_ipv4,
        r.cidr_ipv6,
        r.prefix_list_id,
        r.referenced_security_group_id,
        r.self ? "self" : null,
      ])) == 1
    ])
    error_message = "Each ingress rule must set exactly one source: cidr_ipv4, cidr_ipv6, prefix_list_id, referenced_security_group_id, or self = true."
  }
}

variable "egress_rules" {
  description = "Egress rules; same shape as ingress_rules. Used to restrict egress when allow_all_egress = false (or to add extra scoped egress alongside it)."
  type = list(object({
    preset                       = optional(string)
    description                  = optional(string)
    from_port                    = optional(number)
    to_port                      = optional(number)
    ip_protocol                  = optional(string)
    cidr_ipv4                    = optional(string)
    cidr_ipv6                    = optional(string)
    prefix_list_id               = optional(string)
    referenced_security_group_id = optional(string)
    self                         = optional(bool, false)
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.egress_rules :
      r.preset == null ? true : contains([
        "ssh", "http", "https", "http-alt", "https-alt", "dns-tcp", "dns-udp",
        "ntp", "smtp-tls", "ldap", "ldaps", "nfs", "postgres", "mysql", "mssql",
        "oracle-db", "redis", "memcached", "mongodb", "rabbitmq", "kafka",
        "elasticsearch", "prometheus", "node-exporter", "grafana",
        "kubernetes-api", "rdp", "winrm-http", "winrm-https", "all-icmp",
        "all-traffic",
      ], r.preset)
    ])
    error_message = "Unknown egress preset. See the presets table in the README for valid names."
  }

  validation {
    condition = alltrue([
      for r in var.egress_rules :
      r.preset != null || r.ip_protocol != null
    ])
    error_message = "Egress rules without a preset must set ip_protocol (and from_port/to_port for tcp/udp)."
  }

  validation {
    condition = alltrue([
      for r in var.egress_rules :
      length(compact([
        r.cidr_ipv4,
        r.cidr_ipv6,
        r.prefix_list_id,
        r.referenced_security_group_id,
        r.self ? "self" : null,
      ])) == 1
    ])
    error_message = "Each egress rule must set exactly one destination: cidr_ipv4, cidr_ipv6, prefix_list_id, referenced_security_group_id, or self = true."
  }
}

variable "allow_all_egress" {
  description = "Create allow-all IPv4 + IPv6 egress rules. Set false for least-privilege egress and declare what you need in egress_rules."
  type        = bool
  default     = true
}

variable "revoke_rules_on_delete" {
  description = "Revoke all rules before deleting the group -- helps teardown when groups reference each other."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to the security group and every rule."
  type        = map(string)
  default     = {}
}
