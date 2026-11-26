# PandoraBox one-time setup on Windows: Python check, project venv, dependencies, pandora.toml.
# Run from the project folder:   powershell -ExecutionPolicy Bypass -File .\setup.ps1
# Safe to run again (after a git pull, say): it reuses the venv and only installs what changed.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Find-Python {
    $candidates = @()
    if (Get-Command py -ErrorAction SilentlyContinue) { $candidates += , @("py", "-3") }
    foreach ($name in "python", "python3") {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        # skip the Microsoft Store alias (WindowsApps\python.exe): it only opens the Store
        if ($cmd -and $cmd.Source -notlike "*\WindowsApps\*") { $candidates += , @($cmd.Source) }
    }
    Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe", "$env:ProgramFiles\Python3*\python.exe" `
        -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | ForEach-Object { $candidates += , @($_.FullName) }
    foreach ($c in $candidates) {
        $exe = $c[0]; $pre = @($c | Select-Object -Skip 1)
        $v = & $exe @pre -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
        if ($LASTEXITCODE -eq 0 -and $v -and [version]$v -ge [version]"3.11") { return , @($c) }
    }
    return $null
}

$py = Find-Python
if (-not $py) {
    Write-Host "Python 3.11 or newer not found. Install it, open a NEW PowerShell window, run this again:" -ForegroundColor Red
    Write-Host "  winget install --id Python.Python.3.12 -e"
    exit 1
}
Write-Host "Python: $($py -join ' ')"

if (-not (Test-Path .\.venv\Scripts\python.exe)) {
    Write-Host "Creating the project environment (.venv)..."
    $exe = $py[0]; $pre = @($py | Select-Object -Skip 1)
    & $exe @pre -m venv .venv
    if ($LASTEXITCODE) { Write-Host "Could not create .venv" -ForegroundColor Red; exit 1 }
}
$venv = (Resolve-Path .\.venv\Scripts\python.exe).Path

Write-Host "Installing PandoraBox and its libraries into .venv (first time: a few minutes)..."
& $venv -m pip install --disable-pip-version-check -q -e ".[dev]"
if ($LASTEXITCODE) { Write-Host "pip install failed: see the messages above" -ForegroundColor Red; exit 1 }

if (-not (Test-Path .\pandora.toml)) {
    Copy-Item .\pandora.toml.example .\pandora.toml
    Write-Host "Created pandora.toml from the example."
}

Write-Host ""
Write-Host "Setup done." -ForegroundColor Green
Write-Host "Wired network adapters on this PC (pick the one cabled to the Cisco gear for 'iface' in pandora.toml):"
Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.MediaType -eq "802.3" } |
    ForEach-Object {
        $ip = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -join ", "
        Write-Host ("  {0,-20} {1,-12} {2}" -f $_.Name, $_.Status, $ip)
    }
Write-Host ""
Write-Host "Next, in an Administrator PowerShell in this folder:"
Write-Host "  powershell -ExecutionPolicy Bypass -File .\run.ps1 -Preflight    (check the laptop, fix what it says)"
Write-Host "  powershell -ExecutionPolicy Bypass -File .\run.ps1               (start PandoraBox)"
