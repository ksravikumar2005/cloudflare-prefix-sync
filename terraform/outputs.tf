output "mode" {
  description = "Deployed operating mode."
  value       = var.mode
}

output "cloudflare_ipv4_prefix_list_id" {
  description = "Managed IPv4 prefix list. Reference it from security group rules."
  value       = local.ipv4_prefix_list_id
}

output "cloudflare_ipv6_prefix_list_id" {
  description = "Managed IPv6 prefix list. Reference it from security group rules."
  value       = local.ipv6_prefix_list_id
}

output "backup_bucket_name" {
  description = "S3 bucket with pre-change backups of prefix lists and security groups."
  value       = aws_s3_bucket.prefix_backups.id
}

output "sync_lambda_function_name" {
  description = "Lambda function name (use with aws lambda invoke)."
  value       = aws_lambda_function.prefix_sync.function_name
}

output "sync_lambda_function_arn" {
  description = "Lambda function ARN."
  value       = aws_lambda_function.prefix_sync.arn
}

output "notification_topic_arn" {
  description = "SNS topic that receives the have-vs-needs report and error alarms."
  value       = aws_sns_topic.sync_notifications.arn
}

output "demo_security_group_id" {
  description = "Demo security group (only when demo_vpc_id is set). Use with scripts/demo.py use-deployed."
  value       = try(aws_security_group.demo[0].id, "")
}
