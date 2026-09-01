# Security group with named rule presets, built on the modern standalone
# aws_vpc_security_group_*_rule resources (one API object per rule -- no more
# inline-rule diff churn). Works with Terraform and OpenTofu.

locals {
  # Named presets. from_port/to_port stay null for protocol "-1" rules.
  presets = {
    ssh            = { from_port = 22, to_port = 22, ip_protocol = "tcp", description = "SSH" }
    http           = { from_port = 80, to_port = 80, ip_protocol = "tcp", description = "HTTP" }
    https          = { from_port = 443, to_port = 443, ip_protocol = "tcp", description = "HTTPS" }
    http-alt       = { from_port = 8080, to_port = 8080, ip_protocol = "tcp", description = "HTTP alternate" }
    https-alt      = { from_port = 8443, to_port = 8443, ip_protocol = "tcp", description = "HTTPS alternate" }
    dns-tcp        = { from_port = 53, to_port = 53, ip_protocol = "tcp", description = "DNS (TCP)" }
    dns-udp        = { from_port = 53, to_port = 53, ip_protocol = "udp", description = "DNS (UDP)" }
    ntp            = { from_port = 123, to_port = 123, ip_protocol = "udp", description = "NTP" }
    smtp-tls       = { from_port = 587, to_port = 587, ip_protocol = "tcp", description = "SMTP submission (STARTTLS)" }
    ldap           = { from_port = 389, to_port = 389, ip_protocol = "tcp", description = "LDAP" }
    ldaps          = { from_port = 636, to_port = 636, ip_protocol = "tcp", description = "LDAPS" }
    nfs            = { from_port = 2049, to_port = 2049, ip_protocol = "tcp", description = "NFS" }
    postgres       = { from_port = 5432, to_port = 5432, ip_protocol = "tcp", description = "PostgreSQL" }
    mysql          = { from_port = 3306, to_port = 3306, ip_protocol = "tcp", description = "MySQL/Aurora" }
    mssql          = { from_port = 1433, to_port = 1433, ip_protocol = "tcp", description = "SQL Server" }
    oracle-db      = { from_port = 1521, to_port = 1521, ip_protocol = "tcp", description = "Oracle DB" }
    redis          = { from_port = 6379, to_port = 6379, ip_protocol = "tcp", description = "Redis/Valkey" }
    memcached      = { from_port = 11211, to_port = 11211, ip_protocol = "tcp", description = "Memcached" }
    mongodb        = { from_port = 27017, to_port = 27017, ip_protocol = "tcp", description = "MongoDB" }
    rabbitmq       = { from_port = 5672, to_port = 5672, ip_protocol = "tcp", description = "RabbitMQ (AMQP)" }
    kafka          = { from_port = 9092, to_port = 9092, ip_protocol = "tcp", description = "Kafka" }
    elasticsearch  = { from_port = 9200, to_port = 9200, ip_protocol = "tcp", description = "Elasticsearch/OpenSearch REST" }
    prometheus     = { from_port = 9090, to_port = 9090, ip_protocol = "tcp", description = "Prometheus" }
    node-exporter  = { from_port = 9100, to_port = 9100, ip_protocol = "tcp", description = "Prometheus node exporter" }
    grafana        = { from_port = 3000, to_port = 3000, ip_protocol = "tcp", description = "Grafana" }
    kubernetes-api = { from_port = 6443, to_port = 6443, ip_protocol = "tcp", description = "Kubernetes API server" }
    rdp            = { from_port = 3389, to_port = 3389, ip_protocol = "tcp", description = "RDP" }
    winrm-http     = { from_port = 5985, to_port = 5985, ip_protocol = "tcp", description = "WinRM (HTTP)" }
    winrm-https    = { from_port = 5986, to_port = 5986, ip_protocol = "tcp", description = "WinRM (HTTPS)" }
    all-icmp       = { from_port = -1, to_port = -1, ip_protocol = "icmp", description = "All ICMP" }
    all-traffic    = { from_port = null, to_port = null, ip_protocol = "-1", description = "All traffic" }
  }

  # Resolve preset/explicit rules into one normalized shape. Keys are
  # zero-padded list indexes: reordering rules re-creates them (cheap, atomic).
  ingress_rules = {
    for i, r in var.ingress_rules : format("%02d", i) => {
      from_port                    = r.preset != null ? local.presets[r.preset].from_port : r.from_port
      to_port                      = r.preset != null ? local.presets[r.preset].to_port : r.to_port
      ip_protocol                  = r.preset != null ? local.presets[r.preset].ip_protocol : r.ip_protocol
      description                  = r.description != null ? r.description : (r.preset != null ? local.presets[r.preset].description : "Managed by Terraform")
      cidr_ipv4                    = r.cidr_ipv4
      cidr_ipv6                    = r.cidr_ipv6
      prefix_list_id               = r.prefix_list_id
      referenced_security_group_id = r.referenced_security_group_id
      self                         = r.self
    }
  }

  egress_rules = {
    for i, r in var.egress_rules : format("%02d", i) => {
      from_port                    = r.preset != null ? local.presets[r.preset].from_port : r.from_port
      to_port                      = r.preset != null ? local.presets[r.preset].to_port : r.to_port
      ip_protocol                  = r.preset != null ? local.presets[r.preset].ip_protocol : r.ip_protocol
      description                  = r.description != null ? r.description : (r.preset != null ? local.presets[r.preset].description : "Managed by Terraform")
      cidr_ipv4                    = r.cidr_ipv4
      cidr_ipv6                    = r.cidr_ipv6
      prefix_list_id               = r.prefix_list_id
      referenced_security_group_id = r.referenced_security_group_id
      self                         = r.self
    }
  }
}

resource "aws_security_group" "this" {
  # checkov:skip=CKV2_AWS_5: a standalone security-group module by definition ships the SG unattached — buyers attach it to their instances/ENIs/load balancers via the security_group_id output; the attaching resources live outside this module
  name                   = var.use_name_prefix ? null : var.name
  name_prefix            = var.use_name_prefix ? "${var.name}-" : null
  description            = var.description
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = var.revoke_rules_on_delete

  tags = merge(var.tags, { Name = var.name })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "this" {
  for_each = local.ingress_rules

  security_group_id = aws_security_group.this.id

  description                  = each.value.description
  from_port                    = each.value.from_port
  to_port                      = each.value.to_port
  ip_protocol                  = each.value.ip_protocol
  cidr_ipv4                    = each.value.cidr_ipv4
  cidr_ipv6                    = each.value.cidr_ipv6
  prefix_list_id               = each.value.prefix_list_id
  referenced_security_group_id = each.value.self ? aws_security_group.this.id : each.value.referenced_security_group_id

  tags = merge(var.tags, { Name = "${var.name}-in-${each.key}" })
}

resource "aws_vpc_security_group_egress_rule" "this" {
  for_each = local.egress_rules

  security_group_id = aws_security_group.this.id

  description                  = each.value.description
  from_port                    = each.value.from_port
  to_port                      = each.value.to_port
  ip_protocol                  = each.value.ip_protocol
  cidr_ipv4                    = each.value.cidr_ipv4
  cidr_ipv6                    = each.value.cidr_ipv6
  prefix_list_id               = each.value.prefix_list_id
  referenced_security_group_id = each.value.self ? aws_security_group.this.id : each.value.referenced_security_group_id

  tags = merge(var.tags, { Name = "${var.name}-out-${each.key}" })
}

resource "aws_vpc_security_group_egress_rule" "all_ipv4" {
  count = var.allow_all_egress ? 1 : 0

  security_group_id = aws_security_group.this.id

  description = "Allow all IPv4 egress"
  ip_protocol = "-1"
  cidr_ipv4   = "0.0.0.0/0"

  tags = merge(var.tags, { Name = "${var.name}-out-all-ipv4" })
}

resource "aws_vpc_security_group_egress_rule" "all_ipv6" {
  count = var.allow_all_egress ? 1 : 0

  security_group_id = aws_security_group.this.id

  description = "Allow all IPv6 egress"
  ip_protocol = "-1"
  cidr_ipv6   = "::/0"

  tags = merge(var.tags, { Name = "${var.name}-out-all-ipv6" })
}
