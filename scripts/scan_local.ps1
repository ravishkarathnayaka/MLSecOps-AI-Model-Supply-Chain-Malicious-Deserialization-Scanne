# MLSecOps Local Model Directory Scanner for PowerShell
param(
    [string]$Path = "test_models\",
    [string]$FailOn = "high",
    [string]$Format = "text"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting MLSecOps Static Model Security Audit" -ForegroundColor Cyan
Write-Host " Target : $Path" -ForegroundColor Gray
Write-Host " Fail-on: $FailOn" -ForegroundColor Gray
Write-Host " Format : $Format" -ForegroundColor Gray
Write-Host "==========================================================" -ForegroundColor Cyan

python -m cli.main --path $Path --fail-on $FailOn --format $Format
