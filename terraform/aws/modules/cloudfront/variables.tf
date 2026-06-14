variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "enabled" {
  type    = bool
  default = false
}

variable "ec2_public_ip" {
  type    = string
  default = ""
}

variable "api_subdomain" {
  type    = string
  default = "api"
}

variable "dashboard_subdomain" {
  type    = string
  default = "dashboard"
}

variable "route53_zone_name" {
  type    = string
  default = ""
}

variable "enable_route53" {
  type    = bool
  default = false
}

variable "acm_certificate_arn" {
  type    = string
  default = ""
}
