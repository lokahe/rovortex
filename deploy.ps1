$ErrorActionPreference = "Stop"

$Root = Split-Path $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Host "==> 1. Check Docker and Docker Compose" -ForegroundColor Cyan
docker --version
docker compose version

Write-Host "==> 2. Generate .env"
if (Test-Path "local.properties") {
    Copy-Item "local.properties" ".env"
    Write-Host "    Found local.properties, copied to .env." -ForegroundColor Yellow
} elseif (Test-Path ".env.example") {
    Copy-Item ".env.example" ".env"
    Write-Host "    No local.properties found, generated .env from .env.example."
} else {
    Write-Error "Cannot find .env.example, please copy it first."
    exit 1
}

$env:ROVORTEX_DB_URL = (Get-Content ".env" | Where-Object { $_ -like "ROVORTEX_DB_URL=*" }).TrimStart("ROVORTEX_DB_URL=").Trim()
if ([string]::IsNullOrEmpty($env:ROVORTEX_DB_URL)) {
    $env:ROVORTEX_DB_URL = "postgres://rovortex:***@localhost:5432/rovortex"
}

Write-Host "    Current ROVORTEX_DB_URL = $env:ROVORTEX_DB_URL"

Write-Host "==> 3. Generate sqlx-data.json (sqlx compile-time validation needs this)"
if (-not (Test-Path "sqlx-data.json")) {
    Write-Host "    Generating, please wait..." -ForegroundColor Yellow
    $env:ROVORTEX_DB_URL = $env:ROVORTEX_DB_URL
    cargo sqlx prepare --workspace --locked
    Write-Host "    sqlx-data.json generated."
} else {
    Write-Host "    sqlx-data.json exists, skipping."
}

Write-Host "==> 4. Build and start containers"
docker compose up -d --build

Write-Host "==> 5. Show status"
docker compose ps

Write-Host "==> 6. Show logs"
docker compose logs -f
