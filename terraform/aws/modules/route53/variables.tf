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

variable "zone_name" {
  type    = string
  default = ""
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

variable "cloudfront_domain" {
  type    = string
  default = ""
}

variable "enable_cloudfront" {
  type    = bool
  default = false
}

variable "cloudfront_zone_id" {
  type    = string
  default = ""
}
