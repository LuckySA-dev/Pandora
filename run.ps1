# Start PandoraBox the same safe way every time:
#   - the project's own Python (.venv), never another one with other library versions
#   - Administrator (DHCP/TFTP/SNMP/HTTP ports), unless -NoDhcp
#   - an old PandoraBox still holding the ports is shown and, if you say so, stopped
#   - the three secrets asked once per window, hidden while typed, never written to a file
# Usage (Administrator PowerShell, project folder):
#   powershell -ExecutionPolicy Bypass -File .\run.ps1             start
#   powershell -ExecutionPolicy Bypass -File .\run.ps1 -Preflight  check the laptop only
#   powershell -ExecutionPolicy Bypass -File .\run.ps1 -NoDhcp     UI, console, SNMP, SSH only (no admin needed)
param([switch]$Preflight, [switch]$NoDhcp, [switch]$AssumeIsolated)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$py = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    Write-Host "No .venv yet: run  powershell -ExecutionPolicy Bypass -File .\setup.ps1  first." -ForegroundColor Red
    exit 1
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin -and -not $NoDhcp -and -not $Preflight) {
    Write-Host "Run this in an Administrator PowerShell (DHCP/TFTP need it), or add -NoDhcp." -ForegroundColor Red
    exit 1
}

# ---- an old copy still running? (it keeps ports 67/69/162/80 and answers DHCP next to the new one) ----------------
$port = 80
if (Test-Path .\pandora.toml) {
    $m = Select-String -Path .\pandora.toml -Pattern '^\s*http_port\s*=\s*(\d+)' | Select-Object -First 1
    if ($m) { $port = [int]$m.Matches[0].Groups[1].Value }
}
$owners = @()
$owners += Get-NetUDPEndpoint -LocalPort 67, 69, 162 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess
$owners += Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess
$old = @($owners | Sort-Object -Unique | ForEach-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue } |
         Where-Object { $_.ProcessName -like "python*" })
if ($old.Count -and -not $Preflight) {
    Write-Host "Another PandoraBox (or other Python program) holds the PandoraBox ports:" -ForegroundColor Yellow
    $old | ForEach-Object { Write-Host ("  PID {0}  started {1}" -f $_.Id, $_.StartTime) }
    $answer = Read-Host "Stop it so this one can start? [y/N]"
    if ($answer -notmatch '^(y|yes)$') { Write-Host "Not started."; exit 1 }
    # its python.exe launcher and the real interpreter both go
    $old | ForEach-Object {
        $parent = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        $p = Get-Process -Id $parent -ErrorAction SilentlyContinue
        if ($p -and $p.ProcessName -like "python*") { Stop-Process -Id $parent -Force -ErrorAction SilentlyContinue }
    }
    Start-Sleep -Seconds 1
}

# ---- secrets: asked once per window, hidden, checked for what IOS accepts ------------------------------------------
function Read-Secret($name, $label) {
    $have = [Environment]::GetEnvironmentVariable($name, "Process")
    if ($have -and $have.Length -ge 8) { return }
    while ($true) {
        $s = Read-Host "$label (8+ characters, same value every time)" -AsSecureString
        $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
        try { $v = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
        if ($v.Length -lt 8) { Write-Host "  at least 8 characters" -ForegroundColor Yellow; continue }
        if ($v -match '[\s?"]') { Write-Host "  no spaces, ? or quotes: the device CLI would cut it" -ForegroundColor Yellow; continue }
        [Environment]::SetEnvironmentVariable($name, $v, "Process")
        return
    }
}
Read-Secret "PANDORA_ADMIN_PASSWORD" "Password for the pandora user on the devices"
Read-Secret "PANDORA_SNMP_AUTH" "SNMPv3 auth key"
Read-Secret "PANDORA_SNMP_PRIV" "SNMPv3 priv key"

if ($Preflight) { & $py -m pandora --preflight; exit $LASTEXITCODE }
$extra = @()
if ($NoDhcp) { $extra += "--no-dhcp" }
if ($AssumeIsolated) { $extra += "--assume-isolated" }
Write-Host "Starting PandoraBox (Ctrl+C stops it)..." -ForegroundColor Green
& $py -m pandora @extra
exit $LASTEXITCODE
