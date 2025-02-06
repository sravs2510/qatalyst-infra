terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      configuration_aliases = [aws.alb_region]
    }
  }
}

data "aws_region" "current" {
  provider = aws.alb_region
}
data "aws_s3_bucket" "log_bucket" {
  bucket   = local.log_bucket_name
  provider = aws.alb_region
}

locals {
  lb_target_interval            = lookup(var.lb_target_health, "lb_target_interval")
  lb_target_timeout             = lookup(var.lb_target_health, "lb_target_timeout")
  lb_target_healthy_threshold   = lookup(var.lb_target_health, "lb_target_healthy_threshold")
  lb_target_unhealthy_threshold = lookup(var.lb_target_health, "lb_target_unhealthy_threshold")
  lb_deregistration_delay       = lookup(var.lb_target_health, "lb_deregistration_delay")
}
resource "aws_security_group" "qatalyst_alb_sg" {
  provider    = aws.alb_region
  name        = "qatalyst-alb-sg"
  description = "ALB Security Group"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS From Internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] #Anywhere
  }

  egress {
    description = "All Traffic Outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(tomap({ "Name" : "qatalyst-alb-sg" }), tomap({ "STAGE" : var.STAGE }), var.DEFAULT_TAGS)
}
resource "aws_lb" "qatalyst_alb" {
  provider                   = aws.alb_region
  name                       = "qatalyst-alb"
  internal                   = false
  idle_timeout               = "120"
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.qatalyst_alb_sg.id]
  subnets                    = var.alb_subnets
  enable_deletion_protection = true
  dynamic "access_logs" {
    for_each = var.STAGE == "prod" ? [1] : []
    content {
      bucket  = data.aws_s3_bucket.log_bucket.id
      prefix  = "qatalyst/alb"
      enabled = true
    }
  }
  tags = merge(tomap({ "Name" : "qatalyst-alb" }), tomap({ "STAGE" : var.STAGE }), var.DEFAULT_TAGS)
}

resource "aws_lb_target_group" "qatalyst_tg" {
  provider             = aws.alb_region
  name                 = "qatalyst-tg"
  port                 = 80
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = local.lb_deregistration_delay

  health_check {
    path                = "/health"
    interval            = local.lb_target_interval
    timeout             = local.lb_target_timeout
    healthy_threshold   = local.lb_target_healthy_threshold
    unhealthy_threshold = local.lb_target_unhealthy_threshold
  }
  tags = merge(tomap({ "Name" : "qatalyst-dashboard-tg" }), tomap({ "STAGE" : var.STAGE }), var.DEFAULT_TAGS)
}

resource "aws_lb_target_group" "qatalyst_reports_tg" {
  provider             = aws.alb_region
  name                 = "qatalyst-reports-tg"
  port                 = 80
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = local.lb_deregistration_delay

  health_check {
    path                = "/health"
    interval            = local.lb_target_interval
    timeout             = local.lb_target_timeout
    healthy_threshold   = local.lb_target_healthy_threshold
    unhealthy_threshold = local.lb_target_unhealthy_threshold
  }
  tags = merge(tomap({ "Name" : "qatalyst-reports-tg" }), tomap({ "STAGE" : var.STAGE }), var.DEFAULT_TAGS)
}

resource "aws_lb_target_group" "qatalyst_tester_view_tg" {
  provider             = aws.alb_region
  name                 = "qatalyst-tester-view-tg"
  port                 = 80
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = local.lb_deregistration_delay

  health_check {
    path                = "/health"
    interval            = local.lb_target_interval
    timeout             = local.lb_target_timeout
    healthy_threshold   = local.lb_target_healthy_threshold
    unhealthy_threshold = local.lb_target_unhealthy_threshold
  }
  tags = merge(tomap({ "Name" : "qatalyst-tester-view-tg" }), tomap({ "STAGE" : var.STAGE }), var.DEFAULT_TAGS)
}

resource "aws_lb_target_group" "qatalyst_copilot_tg" {
  provider             = aws.alb_region
  name                 = "qatalyst-copilot-tg"
  port                 = 80
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = local.lb_deregistration_delay

  health_check {
    path                = "/health"
    interval            = local.lb_target_interval
    timeout             = local.lb_target_timeout
    healthy_threshold   = local.lb_target_healthy_threshold
    unhealthy_threshold = local.lb_target_unhealthy_threshold
  }
  tags = merge(tomap({ "Name" : "qatalyst-copilot-tg" }), tomap({ "STAGE" : var.STAGE }), var.DEFAULT_TAGS)
}

resource "aws_lb_listener" "qatalyst_alb_listener" {
  provider          = aws.alb_region
  certificate_arn   = var.alb_certficate_arn
  load_balancer_arn = aws_lb.qatalyst_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.qatalyst_tg.arn
  }
  tags = merge(tomap({ "Name" : "qatalyst-alb-listener" }), tomap({ "STAGE" : var.STAGE }), var.DEFAULT_TAGS)
}

resource "aws_lb_listener_certificate" "qatalyst_reports_listener_certificate" {
  provider        = aws.alb_region
  listener_arn    = aws_lb_listener.qatalyst_alb_listener.arn
  certificate_arn = var.reports_acm_arn
}

resource "aws_lb_listener_certificate" "qatalyst_meet_listener_certificate" {
  provider        = aws.alb_region
  listener_arn    = aws_lb_listener.qatalyst_alb_listener.arn
  certificate_arn = var.meet_acm_arn
}

resource "aws_lb_listener_certificate" "qatalyst_invite_listener_certificate" {
  provider        = aws.alb_region
  listener_arn    = aws_lb_listener.qatalyst_alb_listener.arn
  certificate_arn = var.invite_acm_arn
}

resource "aws_lb_listener_certificate" "qatalyst_tester_view_listener_certificate" {
  provider        = aws.alb_region
  listener_arn    = aws_lb_listener.qatalyst_alb_listener.arn
  certificate_arn = var.tester_view_acm_arn
}

resource "aws_lb_listener_certificate" "qatalyst_calendar_listener_certificate" {
  provider        = aws.alb_region
  listener_arn    = aws_lb_listener.qatalyst_alb_listener.arn
  certificate_arn = var.calendar_acm_arn
}

resource "aws_lb_listener_rule" "qatalyst_alb_listener_reports_rule" {
  listener_arn = aws_lb_listener.qatalyst_alb_listener.arn
  provider     = aws.alb_region
  priority     = 100
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.qatalyst_reports_tg.arn
  }
  condition {
    path_pattern {
      values = [local.path_pattern]
    }
  }
}

resource "aws_lb_listener_rule" "qatalyst_alb_listener_tester_view_rule" {
  listener_arn = aws_lb_listener.qatalyst_alb_listener.arn
  provider     = aws.alb_region
  priority     = 101
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.qatalyst_tester_view_tg.arn
  }
  condition {
    path_pattern {
      values = [local.path_pattern_test, local.path_pattern_testers]
    }
  }
}

resource "aws_lb_listener_rule" "qatalyst_alb_listener_copilot_rule" {
  listener_arn = aws_lb_listener.qatalyst_alb_listener.arn
  provider     = aws.alb_region
  priority     = 102
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.qatalyst_copilot_tg.arn
  }
  condition {
    path_pattern {
      values = [local.path_pattern_copilot]
    }
  }
}

# ALB Domain Mapping
locals {
  datacenter_code      = lookup(var.datacenter_codes, data.aws_region.current.name)
  alb_domain_name      = var.STAGE == "prod" ? join(".", [local.datacenter_code, var.sub_domain, var.base_domain]) : join(".", [local.datacenter_code, var.STAGE, var.sub_domain, var.base_domain])
  path_prefix          = "/"
  path_pattern         = join("", [local.path_prefix, "v1", local.path_prefix, local.datacenter_code, local.path_prefix, "*"])
  path_pattern_testers = join("", [local.path_prefix, "v1", local.path_prefix, "testers", local.path_prefix, "*"])
  path_pattern_test    = join("", [local.path_prefix, "v1", local.path_prefix, "test", local.path_prefix, "*"])
  path_pattern_copilot = join("", [local.path_prefix, "v1", local.path_prefix, "copilot", local.path_prefix, "*"])
  log_bucket_name      = join("-", ["entropik-logs", var.STAGE, local.datacenter_code])
  waf_log_bucket_name  = join("-", ["aws-waf-logs-entropik", var.STAGE, local.datacenter_code])


}

data "aws_route53_zone" "domain_hosted_zone" {
  provider     = aws.alb_region
  name         = var.STAGE == "prod" ? var.base_domain : join(".", [var.STAGE, var.sub_domain, var.base_domain])
  private_zone = false
}

resource "aws_route53_record" "qatalyst_api_domain_record" {
  provider = aws.alb_region
  zone_id  = data.aws_route53_zone.domain_hosted_zone.zone_id
  name     = local.alb_domain_name
  type     = "A"

  alias {
    name                   = aws_lb.qatalyst_alb.dns_name
    zone_id                = aws_lb.qatalyst_alb.zone_id
    evaluate_target_health = false
  }
}

data "aws_sns_topic" "current" {
  name     = "DevOps-Alerts-Topic"
  provider = aws.alb_region
}

resource "aws_cloudwatch_metric_alarm" "target_response_time_alarm" {
  provider            = aws.alb_region
  count               = var.STAGE == "prod" ? 1 : 0
  alarm_name          = "qatalyst-alb-latency-monitoring"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = "300" // 5 minutes
  statistic           = "Average"
  threshold           = 30
  alarm_description   = "Alarm when TargetResponseTime exceeds threshold"
  actions_enabled     = true
  alarm_actions       = [data.aws_sns_topic.current.arn]
  dimensions = {
    LoadBalancer = aws_lb.qatalyst_alb.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "error_monitoring_alarm" {
  provider            = aws.alb_region
  count               = var.STAGE == "prod" ? 1 : 0
  alarm_name          = "qatalyst-alb-error-monitoring"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = "300" // 5 minutes
  statistic           = "Average"
  threshold           = 10
  alarm_description   = "Alarm when error monitoring Time exceeds threshold"
  actions_enabled     = true
  alarm_actions       = [data.aws_sns_topic.current.arn]
  dimensions = {
    LoadBalancer = aws_lb.qatalyst_alb.arn_suffix
  }
}

resource "aws_wafv2_web_acl" "alb_web_acl" {
  provider = aws.alb_region
  name     = "qatalyst-waf-web-acl"
  scope    = "REGIONAL"

  default_action {
    block {}
  }

  custom_response_body {
    key          = "too-many-requests"
    content      = jsonencode({ message = "Too many requests. Try after sometime" })
    content_type = "APPLICATION_JSON"
  }

  rule {
    name     = "rate-based-rule-rate-limiter"
    priority = 1
    action {
      block {
        custom_response {
          response_code            = 429
          custom_response_body_key = "too-many-requests"
          response_header {
            name  = "Access-Control-Allow-Origin"
            value = "*"
          }
        }
      }
    }
    statement {
      rate_based_statement {
        limit                 = 150
        evaluation_window_sec = 60
        aggregate_key_type    = "CUSTOM_KEYS"
        scope_down_statement {
          and_statement {
            statement {
              not_statement {
                statement {
                  byte_match_statement {
                    field_to_match {
                      method {}
                    }
                    positional_constraint = "EXACTLY"
                    search_string         = "OPTIONS"
                    text_transformation {
                      priority = 0
                      type     = "NONE"
                    }
                  }
                }
              }
            }
            statement {
              or_statement {
                statement {
                  byte_match_statement {
                    search_string = "/v1/"
                    field_to_match {
                      uri_path {}
                    }
                    text_transformation {
                      priority = 0
                      type     = "NONE"
                    }
                    positional_constraint = "STARTS_WITH"
                  }
                }
                statement {
                  byte_match_statement {
                    search_string = "/v2/"
                    field_to_match {
                      uri_path {}
                    }
                    text_transformation {
                      priority = 0
                      type     = "NONE"
                    }
                    positional_constraint = "STARTS_WITH"
                  }
                }
              }
            }
          }
        }
        custom_key {
          uri_path {
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }

        custom_key {
          ip {}
        }

        custom_key {
          header {
            name = "User-Agent"
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-based-rule-rate-limiter"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "regular-rule-allow-specific-uri-paths"
    priority = 2
    action {
      allow {}
    }
    statement {
      or_statement {
        statement {
          byte_match_statement {
            field_to_match {
              uri_path {}
            }
            positional_constraint = "STARTS_WITH"
            search_string         = "/v1"
            text_transformation {
              priority = 1
              type     = "NONE"
            }
          }
        }
        statement {
          byte_match_statement {
            field_to_match {
              uri_path {}
            }
            positional_constraint = "STARTS_WITH"
            search_string         = "/v2"
            text_transformation {
              priority = 1
              type     = "NONE"
            }
          }
        }
        statement {
          byte_match_statement {
            field_to_match {
              uri_path {}
            }
            positional_constraint = "STARTS_WITH"
            search_string         = "/docs"
            text_transformation {
              priority = 1
              type     = "NONE"
            }
          }
        }
        statement {
          byte_match_statement {
            field_to_match {
              uri_path {}
            }
            positional_constraint = "STARTS_WITH"
            search_string         = "/openapi.json"
            text_transformation {
              priority = 1
              type     = "NONE"
            }
          }
        }
        statement {
          byte_match_statement {
            field_to_match {
              uri_path {}
            }
            positional_constraint = "STARTS_WITH"
            search_string         = "/health"
            text_transformation {
              priority = 1
              type     = "NONE"
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "regular-rule-block-specific-uri-paths"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "qatalyst-waf-web-acl"
    sampled_requests_enabled   = true
  }
}


########### This is the association code
resource "aws_wafv2_web_acl_association" "web_acl_association" {
  provider     = aws.alb_region
  resource_arn = aws_lb.qatalyst_alb.arn
  web_acl_arn  = aws_wafv2_web_acl.alb_web_acl.arn
}

data "aws_s3_bucket" "waf_log_bucket" {
  bucket   = local.waf_log_bucket_name
  provider = aws.alb_region
}
resource "aws_wafv2_web_acl_logging_configuration" "s3_waf_logging_configuration" {
  provider                = aws.alb_region
  log_destination_configs = [data.aws_s3_bucket.waf_log_bucket.arn]
  resource_arn            = aws_wafv2_web_acl.alb_web_acl.arn
  logging_filter {
    default_behavior = "DROP"

    filter {
      behavior    = "KEEP"
      requirement = "MEETS_ANY"
      condition {
        action_condition {
          action = "BLOCK"
        }
      }
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "healthy_host_count_alarm" {
  provider            = aws.alb_region
  count               = var.STAGE == "prod" ? 1 : 0
  alarm_name          = "qatalyst-alb-healthy-host-monitoring"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = "300" // 5 minutes
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Alarm when health monitoring Time exceeds threshold"
  actions_enabled     = true
  alarm_actions       = [data.aws_sns_topic.current.arn]
  dimensions = {
    LoadBalancer = aws_lb.qatalyst_alb.arn_suffix
    TargetGroup  = aws_lb_target_group.qatalyst_tg.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "testerview_healthy_host_count_alarm" {
  provider            = aws.alb_region
  count               = var.STAGE == "prod" ? 1 : 0
  alarm_name          = "qatalyst-alb-testerview-healthy-host-monitoring"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = "300" // 5 minutes
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Alarm when health monitoring Time exceeds threshold for Testerview"
  actions_enabled     = true
  alarm_actions       = [data.aws_sns_topic.current.arn]
  dimensions = {
    LoadBalancer = aws_lb.qatalyst_alb.arn_suffix
    TargetGroup  = aws_lb_target_group.qatalyst_tester_view_tg.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "reports_healthy_host_count_alarm" {
  provider            = aws.alb_region
  count               = var.STAGE == "prod" ? 1 : 0
  alarm_name          = "qatalyst-alb-reports-healthy-host-monitoring"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = "300" // 5 minutes
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Alarm when health monitoring Time exceeds threshold for Reports"
  actions_enabled     = true
  alarm_actions       = [data.aws_sns_topic.current.arn]
  dimensions = {
    LoadBalancer = aws_lb.qatalyst_alb.arn_suffix
    TargetGroup  = aws_lb_target_group.qatalyst_reports_tg.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "copilot_healthy_host_count_alarm" {
  provider            = aws.alb_region
  count               = var.STAGE == "prod" ? 1 : 0
  alarm_name          = "qatalyst-alb-copilot-healthy-host-monitoring"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = "300" // 5 minutes
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Alarm when health monitoring Time exceeds threshold for Copilot"
  actions_enabled     = true
  alarm_actions       = [data.aws_sns_topic.current.arn]
  dimensions = {
    LoadBalancer = aws_lb.qatalyst_alb.arn_suffix
    TargetGroup  = aws_lb_target_group.qatalyst_copilot_tg.arn_suffix
  }
}