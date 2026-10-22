$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot
$venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
$bundledPython = 'C:\Users\Ishan\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
if (Test-Path -LiteralPath $venvPython) {
    $pythonExecutable = $venvPython
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonExecutable = (Get-Command python).Source
} elseif (Test-Path -LiteralPath $bundledPython) {
    $pythonExecutable = $bundledPython
} else {
    throw 'Python was not found. Install Python 3.11+ and follow README setup.'
}
$localPackages = Join-Path $projectRoot '.venv\Lib\site-packages'
if (Test-Path -LiteralPath $localPackages) { $env:PYTHONPATH = $localPackages }
$env:XDG_CONFIG_HOME = $projectRoot
$env:XDG_CACHE_HOME = $projectRoot
& $pythonExecutable -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
