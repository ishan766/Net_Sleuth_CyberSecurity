$ErrorActionPreference = 'Stop'
$frontendRoot = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'frontend'
Set-Location -LiteralPath $frontendRoot
npm run build
if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
npm run start
