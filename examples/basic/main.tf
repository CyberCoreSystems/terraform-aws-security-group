terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

module "app_sg" {
  source = "../../"

  name        = "example-app"
  description = "Example application tier"
  vpc_id      = "vpc-0123456789abcdef0"

  ingress_rules = [
    { preset = "https", cidr_ipv4 = "0.0.0.0/0" },
    { preset = "ssh", cidr_ipv4 = "10.0.0.0/8", description = "SSH from corp ranges" },
    { preset = "postgres", referenced_security_group_id = "sg-0fedcba9876543210" },
    { from_port = 9000, to_port = 9010, ip_protocol = "tcp", self = true, description = "Cluster gossip" },
  ]

  tags = {
    Environment = "example"
    ManagedBy   = "iac-bazaar"
  }
}

output "security_group_id" {
  value = module.app_sg.security_group_id
}
