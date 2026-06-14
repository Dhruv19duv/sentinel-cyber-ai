variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "security_group_id" {
  type = string
}

variable "enabled" {
  type    = bool
  default = false
}

variable "instance_class" {
  type    = string
  default = "db.t3.micro"
}

variable "allocated_storage" {
  type    = number
  default = 20
}

variable "db_name" {
  type    = string
  default = "sentinel"
}

variable "master_username" {
  type    = string
  default = "sentinel"
}

variable "master_password" {
  type    = string
  default = ""
  sensitive = true
}
