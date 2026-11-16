<#
.SYNOPSIS
    cloudflare-prefix-sync - CloudFormation deployer for Windows PowerShell / PowerShell 7.
.DESCRIPTION
    Packages src/ (scripts/package_lambda.py), uploads it to an existing S3 bucket, and deploys
    templates/cloudflare-prefix-sync-template.yaml with the AWS CLI. Without -Execute it only
    packages the code and validates the template.
.EXAMPLE
    .\scripts\deploy_cli.ps1 -ArtifactBucket my-artifacts-us-east-1 -Mode audit -SecurityGroupIds "sg-0123" -NotificationEmail sec@example.com
.EXAMPLE
    .\scripts\deploy_cli.ps1 -ArtifactBucket my-artifacts-us-east-1 -Mode enforce -ManagedSecurityGroupIds "sg-0123" -LambdaDryRun -Execute
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ArtifactBucket,
    [string]$StackName = "cloudflare-prefix-sync",
    [string]$Region = $(if ($env:AWS_REGION) { $env:AWS_REGION } elseif ($env:AWS_DEFAULT_REGION) { $env:AWS_DEFAULT_REGION } else { "us-east-1" }),
    [ValidateSet("discover", "audit", "sync", "attach", "enforce")][string]$Mode = "audit",
    [switch]$LambdaDryRun,
    [string]$SecurityGroupIds = "",
    [string]$ManagedSecurityGroupIds = "",
    [string]$ComparePrefixListIds = "",
    [string]$ExistingIpv4PrefixListId = "",
    [string]$ExistingIpv6PrefixListId = "",
    [string]$NotificationEmail = "",
    [ValidateSet("never", "alerts", "drift", "always")][string]$NotifyOn = "alerts",
    [hashtable]$Tags = @{},
    [hashtable]$Parameters = @{},
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$TemplateFile = Join-Path $RepoRoot "templates\cloudflare-prefix-sync-template.yaml"

Write-Host "[1/4] Packaging Lambda code..."
$pkg = python (Join-Path $RepoRoot "scripts\package_lambda.py") | Out-String | ConvertFrom-Json

$params = [ordered]@{
    Mode                    = $Mode
    DryRun                  = $(if ($LambdaDryRun) { "true" } else { "false" })
    CodeS3Bucket            = $ArtifactBucket
    CodeS3Key               = $pkg.key
    SecurityGroupIds        = $SecurityGroupIds
    ManagedSecurityGroupIds = $ManagedSecurityGroupIds
    ComparePrefixListIds    = $ComparePrefixListIds
    NotificationEmail       = $NotificationEmail
    NotifyOn                = $NotifyOn
}
if ($ExistingIpv4PrefixListId -or $ExistingIpv6PrefixListId) {
    $params.CreatePrefixLists = "false"
    $params.ExistingIpv4PrefixListId = $ExistingIpv4PrefixListId
    $params.ExistingIpv6PrefixListId = $ExistingIpv6PrefixListId
}
foreach ($k in $Parameters.Keys) { $params[$k] = [string]$Parameters[$k] }
$overrides = @($params.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" })

$allTags = @{ Project = "cloudflare-prefix-sync" }
foreach ($k in $Tags.Keys) { $allTags[$k] = [string]$Tags[$k] }
$tagArgs = @($allTags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" })

Write-Host "[2/4] Validating template..."
aws cloudformation validate-template --region $Region --template-body "file://$TemplateFile" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Template validation failed." }

Write-Host "  stack:      $StackName ($Region)"
Write-Host "  code:       s3://$ArtifactBucket/$($pkg.key)"
Write-Host "  parameters: $($overrides -join ' ')"
Write-Host "  tags:       $($tagArgs -join ' ')"

if (-not $Execute) {
    Write-Host "Preview only. Re-run with -Execute to upload and deploy."
    exit 0
}

Write-Host "[3/4] Uploading code and deploying stack..."
aws s3 cp --region $Region $pkg.local_path "s3://$ArtifactBucket/$($pkg.key)" --sse AES256
if ($LASTEXITCODE -ne 0) { throw "Upload failed." }

aws cloudformation deploy --region $Region `
    --template-file $TemplateFile `
    --stack-name $StackName `
    --capabilities CAPABILITY_NAMED_IAM `
    --no-fail-on-empty-changeset `
    --parameter-overrides $overrides `
    --tags $tagArgs
if ($LASTEXITCODE -ne 0) { throw "Stack deployment failed." }

$functionName = aws cloudformation describe-stacks --region $Region --stack-name $StackName `
    --query "Stacks[0].Outputs[?OutputKey=='SyncLambdaFunctionName'].OutputValue" --output text

Write-Host "[4/4] Running $functionName once..."
$out = Join-Path $env:TEMP "cf-prefix-sync-result.json"
aws lambda invoke --region $Region --function-name $functionName `
    --cli-binary-format raw-in-base64-out --payload '{}' $out | Out-Null
$result = Get-Content $out -Raw | ConvertFrom-Json
if ($result.errorMessage) { Write-Host "Lambda error: $($result.errorMessage)" }
elseif ($result.report) { Write-Host $result.report.headline }
else { Write-Host $result.status }
