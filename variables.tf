variable "name" {
  type        = string
  description = "name. used for resource prefix"
}

variable "iam_role_name" {
  type        = string
  description = "iam role name"
}

variable "idp_issuer" {
  type        = string
  description = "Himari URL (upstream token iss)"
}

variable "domain_name" {
  type        = string
  description = "Domain name for this deployment"
}

variable "session_duration" {
  type        = number
  description = "AssumeRole session duration"
  default     = 3600 * 12
}

variable "cloudfront_log_bucket" {
  type        = string
  description = "CloudFront distribution log bucket"
}

variable "cloudfront_log_prefix" {
  type        = string
  description = "CloudFront distribution log prefix"
}

variable "cloudfront_certificate_arn" {
  type        = string
  description = "CloudFront ACM Certificate ARN"
}

variable "header_html" {
  type        = string
  default     = ""
  description = "<header> HTML"
}

variable "footer_html" {
  type        = string
  default     = ""
  description = "<footer> HTML"
}
