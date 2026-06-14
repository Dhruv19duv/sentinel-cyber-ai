variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "bucket_name_prefix" {
  type    = string
  default = "sentinel"
}

variable "enable_versioning" {
  type    = bool
  default = true
}

variable "create_buckets" {
  type    = bool
  default = true
}
