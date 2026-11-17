data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition
  arn_prefix = "arn:${local.partition}:ec2:${local.region}:${local.account_id}"

  # Capability ladder (mirrors src/modes.py)
  can_write_prefix_lists = contains(["sync", "attach", "enforce"], var.mode)
  can_attach             = contains(["attach", "enforce"], var.mode)
  can_revoke             = var.mode == "enforce"

  # Prefix lists: created here, or existing ones supplied by the user
  ipv4_prefix_list_id      = var.create_prefix_lists ? aws_ec2_managed_prefix_list.cloudflare_ipv4[0].id : trimspace(var.existing_ipv4_prefix_list_id)
  ipv6_prefix_list_id      = var.create_prefix_lists ? aws_ec2_managed_prefix_list.cloudflare_ipv6[0].id : trimspace(var.existing_ipv6_prefix_list_id)
  managed_prefix_list_ids  = compact([local.ipv4_prefix_list_id, local.ipv6_prefix_list_id])
  managed_prefix_list_arns = [for id in local.managed_prefix_list_ids : "${local.arn_prefix}:prefix-list/${id}"]

  # Known at plan time. count / for_each must not depend on IDs that only exist after apply.
  has_ipv4         = var.create_prefix_lists || trimspace(var.existing_ipv4_prefix_list_id) != ""
  has_ipv6         = var.create_prefix_lists || trimspace(var.existing_ipv6_prefix_list_id) != ""
  managed_families = concat(local.has_ipv4 ? ["ipv4"] : [], local.has_ipv6 ? ["ipv6"] : [])
  prefix_list_by_family = {
    ipv4 = local.ipv4_prefix_list_id
    ipv6 = local.ipv6_prefix_list_id
  }

  clean = {
    security_group_ids         = [for s in var.security_group_ids : trimspace(s) if trimspace(s) != ""]
    managed_security_group_ids = [for s in var.managed_security_group_ids : trimspace(s) if trimspace(s) != ""]
    compare_prefix_list_ids    = [for s in var.compare_prefix_list_ids : trimspace(s) if trimspace(s) != ""]
    tf_attach_sg_ids           = toset([for s in var.terraform_attach_security_group_ids : trimspace(s) if trimspace(s) != ""])
  }

  # Demo (docs/DEMO.md): a throwaway security group, and a tag that lets scripts/demo.py break things
  create_demo = trimspace(var.demo_vpc_id) != ""
  demo_tags   = local.create_demo ? { "cloudflare-prefix-sync-demo" = var.name_prefix } : {}
  demo_sg_ids = aws_security_group.demo[*].id

  legacy_sg_id       = trimspace(var.target_alb_security_group_id)
  attach_legacy_sg   = var.auto_attach_to_alb_security_group && local.legacy_sg_id != ""
  audited_sg_ids     = distinct(compact(concat(local.clean.security_group_ids, [local.legacy_sg_id], tolist(local.clean.tf_attach_sg_ids), local.demo_sg_ids)))
  managed_sg_ids_all = concat(local.clean.managed_security_group_ids, local.demo_sg_ids)
  managed_sg_arns    = [for id in local.managed_sg_ids_all : "${local.arn_prefix}:security-group/${id}"]
  use_tag_scope      = trimspace(var.managed_tag_key) != ""
  tf_attach_pairs = {
    for pair in setproduct(tolist(local.clean.tf_attach_sg_ids), local.managed_families, var.ingress_ports) :
    "${pair[0]}|${pair[1]}|${pair[2]}" => { sg = pair[0], pl = local.prefix_list_by_family[pair[1]], port = pair[2] }
  }

  has_email        = trimspace(var.notification_email) != ""
  backup_bucket_id = "cf-prefix-sync-backups-${local.account_id}-${local.region}"

  common_tags = merge({
    Project   = "cloudflare-prefix-sync"
    ManagedBy = "terraform"
  }, var.tags)

  seed_ipv4_cidrs = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13", "104.24.0.0/14",
    "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
    "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
  ]
  seed_ipv6_cidrs = [
    "2400:cb00::/32", "2405:8100::/32", "2405:b500::/32", "2606:4700::/32",
    "2803:f800::/32", "2a06:98c0::/29", "2c0f:f248::/32",
  ]
}

check "prefix_lists_for_mode" {
  assert {
    condition     = !local.can_write_prefix_lists || length(local.managed_families) > 0
    error_message = "mode ${var.mode} updates prefix lists: set create_prefix_lists = true or supply existing_ipv4_prefix_list_id / existing_ipv6_prefix_list_id."
  }
}

# -----------------------------------------------------------------------------
# 1. Managed prefix lists (seeded; the Lambda keeps them current)
#    ignore_changes stops later applies from overwriting the Lambda's updates.
# -----------------------------------------------------------------------------
resource "aws_ec2_managed_prefix_list" "cloudflare_ipv4" {
  count          = var.create_prefix_lists ? 1 : 0
  name           = "${var.name_prefix}-cloudflare-ipv4"
  address_family = "IPv4"
  max_entries    = var.initial_ipv4_max_entries

  dynamic "entry" {
    for_each = toset(local.seed_ipv4_cidrs)
    content {
      cidr        = entry.value
      description = "Cloudflare"
    }
  }

  tags = merge(local.common_tags, local.demo_tags, { Name = "${var.name_prefix}-cloudflare-ipv4" })

  lifecycle {
    ignore_changes = [entry, max_entries]
  }
}

resource "aws_ec2_managed_prefix_list" "cloudflare_ipv6" {
  count          = var.create_prefix_lists ? 1 : 0
  name           = "${var.name_prefix}-cloudflare-ipv6"
  address_family = "IPv6"
  max_entries    = var.initial_ipv6_max_entries

  dynamic "entry" {
    for_each = toset(local.seed_ipv6_cidrs)
    content {
      cidr        = entry.value
      description = "Cloudflare"
    }
  }

  tags = merge(local.common_tags, local.demo_tags, { Name = "${var.name_prefix}-cloudflare-ipv6" })

  lifecycle {
    ignore_changes = [entry, max_entries]
  }
}

moved {
  from = aws_ec2_managed_prefix_list.cloudflare_ipv4
  to   = aws_ec2_managed_prefix_list.cloudflare_ipv4[0]
}

moved {
  from = aws_ec2_managed_prefix_list.cloudflare_ipv6
  to   = aws_ec2_managed_prefix_list.cloudflare_ipv6[0]
}

# -----------------------------------------------------------------------------
# 2. Optional static ingress rules managed by Terraform
# -----------------------------------------------------------------------------
resource "aws_vpc_security_group_ingress_rule" "cloudflare" {
  for_each          = local.tf_attach_pairs
  security_group_id = each.value.sg
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
  prefix_list_id    = each.value.pl
  description       = "Cloudflare (managed by Terraform)"
  tags              = local.common_tags
}

# v1 compatibility: same addresses as before so existing rules are not recreated
resource "aws_vpc_security_group_ingress_rule" "alb_from_cloudflare_ipv4" {
  count             = local.attach_legacy_sg && local.has_ipv4 ? 1 : 0
  security_group_id = local.legacy_sg_id
  ip_protocol       = "tcp"
  from_port         = var.alb_ingress_port
  to_port           = var.alb_ingress_port
  prefix_list_id    = local.ipv4_prefix_list_id
  description       = "Allow HTTPS from Cloudflare IPv4 Customer-Managed Prefix List"
  tags              = local.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "alb_from_cloudflare_ipv6" {
  count             = local.attach_legacy_sg && local.has_ipv6 ? 1 : 0
  security_group_id = local.legacy_sg_id
  ip_protocol       = "tcp"
  from_port         = var.alb_ingress_port
  to_port           = var.alb_ingress_port
  prefix_list_id    = local.ipv6_prefix_list_id
  description       = "Allow HTTPS from Cloudflare IPv6 Customer-Managed Prefix List"
  tags              = local.common_tags
}

# -----------------------------------------------------------------------------
# 2b. Demo security group (only when demo_vpc_id is set; see docs/DEMO.md)
#     No inline rules, so changes made by the demo or by attach/enforce do not
#     fight with Terraform. The Cloudflare rules are separate resources.
# -----------------------------------------------------------------------------
resource "aws_security_group" "demo" {
  count       = local.create_demo ? 1 : 0
  name        = "${var.name_prefix}-demo"
  description = "cloudflare-prefix-sync demo security group (safe to delete)"
  vpc_id      = trimspace(var.demo_vpc_id)
  tags        = merge(local.common_tags, local.demo_tags, { Name = "${var.name_prefix}-demo" })
}

resource "aws_vpc_security_group_ingress_rule" "demo_ipv4" {
  count             = local.create_demo && local.has_ipv4 ? length(var.ingress_ports) : 0
  security_group_id = aws_security_group.demo[0].id
  ip_protocol       = "tcp"
  from_port         = var.ingress_ports[count.index]
  to_port           = var.ingress_ports[count.index]
  prefix_list_id    = local.ipv4_prefix_list_id
  description       = "Cloudflare IPv4 (demo)"
  tags              = local.common_tags
}

resource "aws_vpc_security_group_ingress_rule" "demo_ipv6" {
  count             = local.create_demo && local.has_ipv6 ? length(var.ingress_ports) : 0
  security_group_id = aws_security_group.demo[0].id
  ip_protocol       = "tcp"
  from_port         = var.ingress_ports[count.index]
  to_port           = var.ingress_ports[count.index]
  prefix_list_id    = local.ipv6_prefix_list_id
  description       = "Cloudflare IPv6 (demo)"
  tags              = local.common_tags
}

# -----------------------------------------------------------------------------
# 3. Backup bucket (versioned, encrypted, private, TLS-only)
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "prefix_backups" {
  bucket = local.backup_bucket_id
  tags   = merge(local.common_tags, { Name = "${var.name_prefix}-backups" })
}

resource "aws_s3_bucket_versioning" "prefix_backups" {
  bucket = aws_s3_bucket.prefix_backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "prefix_backups" {
  bucket = aws_s3_bucket.prefix_backups.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "prefix_backups" {
  bucket                  = aws_s3_bucket.prefix_backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "prefix_backups" {
  bucket = aws_s3_bucket.prefix_backups.id

  rule {
    id     = "ExpireOldBackups"
    status = "Enabled"

    filter {}

    expiration {
      days = var.backup_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_s3_bucket_policy" "prefix_backups_tls_only" {
  bucket = aws_s3_bucket.prefix_backups.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EnforceTLSRequestsOnly"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.prefix_backups.arn, "${aws_s3_bucket.prefix_backups.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# -----------------------------------------------------------------------------
# 4. SNS topic for the have-vs-needs report and alarms
# -----------------------------------------------------------------------------
# A customer managed key is needed because CloudWatch alarms cannot publish to topics
# encrypted with the AWS managed aws/sns key.
data "aws_iam_policy_document" "sns_key" {
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowCloudWatchAlarms"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_kms_key" "sns" {
  description         = "${var.name_prefix} SNS topic encryption"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.sns_key.json
  tags                = local.common_tags
}

resource "aws_kms_alias" "sns" {
  name          = "alias/${var.name_prefix}-sns"
  target_key_id = aws_kms_key.sns.key_id
}

resource "aws_sns_topic" "sync_notifications" {
  name              = "${var.name_prefix}-notifications"
  kms_master_key_id = aws_kms_key.sns.arn
  tags              = local.common_tags
}

resource "aws_sns_topic_subscription" "email_alert" {
  count     = local.has_email ? 1 : 0
  topic_arn = aws_sns_topic.sync_notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# -----------------------------------------------------------------------------
# 5. IAM: permissions follow the deployed mode
# -----------------------------------------------------------------------------
resource "aws_iam_role" "lambda_exec" {
  name = "${var.name_prefix}-lambda-${local.region}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "lambda_basic_logs" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid = "ReadOnlyInventory"
    actions = [
      "ec2:DescribeManagedPrefixLists",
      "ec2:GetManagedPrefixListEntries",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeInstances",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeRules",
      "cloudfront:ListDistributions",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "WriteBackups"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.prefix_backups.arn, "${aws_s3_bucket.prefix_backups.arn}/*"]
  }

  statement {
    sid       = "PublishReports"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.sync_notifications.arn]
  }

  statement {
    sid       = "EncryptReports"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = [aws_kms_key.sns.arn]
  }

  dynamic "statement" {
    for_each = local.can_write_prefix_lists && length(local.managed_families) > 0 ? [1] : []
    content {
      sid       = "ModifyManagedPrefixListsOnly"
      actions   = ["ec2:ModifyManagedPrefixList", "ec2:RestoreManagedPrefixListVersion"]
      resources = local.managed_prefix_list_arns
    }
  }

  dynamic "statement" {
    for_each = local.can_attach && length(local.managed_sg_arns) > 0 ? [1] : []
    content {
      sid       = "ChangeListedSecurityGroups"
      actions   = local.can_revoke ? ["ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress"] : ["ec2:AuthorizeSecurityGroupIngress"]
      resources = local.managed_sg_arns
    }
  }

  dynamic "statement" {
    for_each = local.can_attach && local.use_tag_scope ? [1] : []
    content {
      sid       = "ChangeTaggedSecurityGroups"
      actions   = local.can_revoke ? ["ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress"] : ["ec2:AuthorizeSecurityGroupIngress"]
      resources = ["${local.arn_prefix}:security-group/*"]
      condition {
        test     = "StringEquals"
        variable = "aws:ResourceTag/${var.managed_tag_key}"
        values   = [var.managed_tag_value]
      }
    }
  }

  # The security group ARN above is what limits scope. Rule and prefix list ARNs alone grant nothing.
  dynamic "statement" {
    for_each = local.can_attach ? [1] : []
    content {
      sid       = "SecurityGroupRuleResources"
      actions   = local.can_revoke ? ["ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress"] : ["ec2:AuthorizeSecurityGroupIngress"]
      resources = concat(["${local.arn_prefix}:security-group-rule/*"], local.managed_prefix_list_arns)
    }
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "cloudflare-prefix-sync-${var.mode}"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda.json
}

# -----------------------------------------------------------------------------
# 6. Lambda (packages ../src)
# -----------------------------------------------------------------------------
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/.terraform/cloudflare_prefix_sync_lambda.zip"
  excludes    = ["__pycache__"]
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.name_prefix}-sync"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

resource "aws_lambda_function" "prefix_sync" {
  function_name    = "${var.name_prefix}-sync"
  description      = "Cloudflare-only ingress: ${var.mode} mode"
  role             = aws_iam_role.lambda_exec.arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "lambda_handler.lambda_handler"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  memory_size      = 256
  timeout          = 180

  environment {
    variables = {
      MODE                              = var.mode
      DRY_RUN                           = tostring(var.dry_run)
      IPV4_PREFIX_LIST_ID               = local.ipv4_prefix_list_id
      IPV6_PREFIX_LIST_ID               = local.ipv6_prefix_list_id
      COMPARE_PREFIX_LIST_IDS           = join(",", local.clean.compare_prefix_list_ids)
      SECURITY_GROUP_IDS                = join(",", local.audited_sg_ids)
      MANAGED_SECURITY_GROUP_IDS        = join(",", local.managed_sg_ids_all)
      MANAGED_TAG_KEY                   = trimspace(var.managed_tag_key)
      MANAGED_TAG_VALUE                 = var.managed_tag_value
      INGRESS_PORTS                     = join(",", [for p in var.ingress_ports : tostring(p)])
      ALLOWED_CIDRS                     = join(",", var.allowed_cidrs)
      ALLOWED_PREFIX_LIST_IDS           = join(",", var.allowed_prefix_list_ids)
      ALLOWED_SOURCE_SECURITY_GROUP_IDS = join(",", var.allowed_source_security_group_ids)
      REVOKE_PRIVATE_CIDRS              = tostring(var.revoke_private_cidrs)
      REVOKE_SECURITY_GROUP_SOURCES     = tostring(var.revoke_security_group_sources)
      MAX_REVOCATIONS_PER_RUN           = tostring(var.max_revocations_per_run)
      AUDIT_ENABLED                     = tostring(var.audit_enabled)
      AUDIT_ALL_LOAD_BALANCERS          = tostring(var.audit_all_load_balancers)
      BACKUP_S3_BUCKET                  = aws_s3_bucket.prefix_backups.id
      BACKUP_S3_PREFIX                  = "backups"
      SNS_TOPIC_ARN                     = aws_sns_topic.sync_notifications.arn
      NOTIFY_ON                         = var.notify_on
      NOTIFY_FORMAT                     = var.notify_format
      MIN_IPV4_CIDRS                    = tostring(var.min_ipv4_cidrs)
      MIN_IPV6_CIDRS                    = tostring(var.min_ipv6_cidrs)
      MAX_REMOVAL_RATIO                 = var.max_removal_ratio
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.lambda]
  tags       = local.common_tags
}

# Alarm if the function fails (for example a guardrail tripped or Cloudflare was unreachable)
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.name_prefix}-errors"
  alarm_description   = "cloudflare-prefix-sync Lambda failed. Check its CloudWatch Logs."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.prefix_sync.function_name }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.sync_notifications.arn]
  tags                = local.common_tags
}

# -----------------------------------------------------------------------------
# 7. Schedule
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name_prefix}-schedule"
  description         = "Runs cloudflare-prefix-sync (${var.mode})."
  schedule_expression = var.schedule_expression
  state               = "ENABLED"
  tags                = local.common_tags
}

resource "aws_cloudwatch_event_target" "invoke_lambda" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "PrefixSyncLambdaTarget"
  arn       = aws_lambda_function.prefix_sync.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.prefix_sync.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
