# Open RsHash documentation in browser
# Usage: .\open-docs.ps1

Write-Host "Opening RsHash Documentation..." -ForegroundColor Cyan

# Generate docs if needed
if (-not (Test-Path "target/doc/rshash/index.html")) {
    Write-Host "Generating documentation..." -ForegroundColor Yellow
    cargo doc --no-deps
}

# Open in default browser
$docPath = Join-Path $PSScriptRoot "target/doc/rshash/index.html"
Start-Process $docPath

Write-Host "Documentation opened!" -ForegroundColor Green
Write-Host ""
Write-Host "Other docs:" -ForegroundColor Cyan
Write-Host "  - README.md"
Write-Host "  - QUICKSTART.md"
Write-Host "  - CONTRIBUTING.md"
