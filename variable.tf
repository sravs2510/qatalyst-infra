variable "DEFAULT_TAGS" {
  type        = map(any)
  description = "Default Tags for all resources"
}

variable "STAGE" {
  type        = string
  description = "Stage for deployment"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID"
}

variable "alb_subnets" {
  type        = list(string)
  description = "List of public subnets for ALB"
}

variable "alb_certficate_arn" {
  type        = string
  description = "ALB Certficate ARN"
}

variable "base_domain" {
  type        = string
  description = "Base domain"
}

variable "sub_domain" {
  type        = string
  description = "Sub Domain name"
}

variable "datacenter_codes" {
  type        = map(string)
  description = "Data center code values"
}

variable "reports_acm_arn" {
  type        = string
  description = "Reports ACM "
}

variable "meet_acm_arn" {
  type        = string
  description = "Meet ACM"
}

variable "lb_target_health" {
  type        = map(string)
  description = "ALB target health checks"
}

variable "invite_acm_arn" {
  type        = string
  description = "Invite ACM "
}

variable "tester_view_acm_arn" {
  type        = string
  description = "Testerview ACM "
}

variable "calendar_acm_arn" {
  type        = string
  description = "Calendar ACM "
}