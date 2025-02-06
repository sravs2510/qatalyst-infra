output "qatalyst_alb_sg_id" {
  value = aws_security_group.qatalyst_alb_sg.id
}

output "qatalyst_alb_target_group_arn" {
  value = aws_lb_target_group.qatalyst_tg.arn
}

output "qatalyst_alb_arn" {
  value = aws_lb.qatalyst_alb.arn
}

output "qatalyst_alb_arn_suffix" {
  value = aws_lb.qatalyst_alb.arn_suffix
}

output "qatalyst_tg_arn_suffix" {
  value = aws_lb_target_group.qatalyst_tg.arn_suffix
}

output "qatalyst_alb_target_group_reports_arn" {
  value = aws_lb_target_group.qatalyst_reports_tg.arn
}

output "qatalyst_alb_dns_name" {
  value = aws_lb.qatalyst_alb.dns_name
}

output "qatalyst_alb_target_group_reports_arn_suffix" {
  value = aws_lb_target_group.qatalyst_reports_tg.arn_suffix
}

output "qatalyst_alb_target_group_tester_view_arn" {
  value = aws_lb_target_group.qatalyst_tester_view_tg.arn
}

output "qatalyst_alb_target_group_tester_view_arn_suffix" {
  value = aws_lb_target_group.qatalyst_tester_view_tg.arn_suffix
}

output "qatalyst_alb_target_group_copilot_arn_suffix" {
  value = aws_lb_target_group.qatalyst_copilot_tg.arn_suffix
}

output "qatalyst_alb_target_group_copilot_arn" {
  value = aws_lb_target_group.qatalyst_copilot_tg.arn
}