variable "vpc_cidr_block" {
  type        = string
  description = "CIDR block for VPC"
  default     = "10.0.0.0/16"
}

variable "region" {
  type        = string
  description = ""
}

variable "profile" {
  type        = string
  description = ""
}
variable "az1" {
  type        = string
  description = ""
}
variable "az2" {
  type        = string
  description = ""
}
variable "vpcConfig" {
  type = object({
    enable_dns_hostnames             = bool
    enable_dns_support               = bool
    enable_classiclink_dns_support   = bool
    assign_generated_ipv6_cidr_block = bool
  })
}

variable "subnet_cidr" {
  type = map(string)
}

variable "vpc_name" {
  type = string
}

variable "ig_name" {
  type = string
}

variable "route_table_name" {
  type = string
}

variable "destination_cidr_block" {
  type = string
}

variable "map_public_ip_on_launch" {
  type = bool
}


variable "rds_identifier" {
  type = string
}

variable "rds_username" {
  type = string
}

variable "rds_password" {
  type = string
}

variable "s3_domain" {
  type = string
}

variable "s3_name" {
  type = string
}

variable "ec2_ami_id" {
  type = string
}

variable "ec2_ssh_key" {
  type = string
}

variable "alarm_low_period" {
  type = number
}

variable "alarm_low_evaluation_period" {
  type = number
}

variable "alarm_low_threshold" {
  type = number
}

variable "alarm_high_period" {
  type = number
}

variable "alarm_high_evaluation_period" {
  type = number
}

variable "alarm_high_threshold" {
  type = number
}

variable "account_id" {
  type = string
}