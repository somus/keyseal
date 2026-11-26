# Builds the helper's MSIX package with build-msix.ps1, signs it with a
# throwaway certificate trusted on this machine and installs it, as the
# Store would deliver it. Then checks that a keyseal:// link opened through
# the shell starts the packaged helper, which logs the damaged link to the
# package's own config folder; that a PKCS#11 driver under Program Files
# loads inside the package; that `keyseal update`, `install` and
# `uninstall` leave those to the Store; and that the package uninstalls.
#
#   scripts/ci/windows-msix-smoke.ps1
#
# Windows only, as administrator: it trusts a certificate for the whole
# machine, so CI runs it on a throwaway runner. Needs OpenSC installed.
$ErrorActionPreference = 'Stop'

function Check($condition, $message) {
  if (-not $condition) { throw $message }
}

$root = Resolve-Path "$PSScriptRoot/../.."
Push-Location "$root/helper"
cargo build -p keyseal-helper
Check ($LASTEXITCODE -eq 0) 'The helper did not build.'
Pop-Location
$built = "$root/helper/target/debug/keyseal.exe"
$version = ((& $built --version | Out-String).Trim()) -replace '^keyseal ', ''

$work = Join-Path $env:RUNNER_TEMP 'msix'
New-Item -ItemType Directory -Force $work | Out-Null
# CI has no notices file; the release has the real one.
$notices = Join-Path $work 'THIRD-PARTY-NOTICES.txt'
Set-Content $notices 'Third-party notices'
$package = & "$root/helper/packaging/windows/build-msix.ps1" $built $notices $version $work
Check (Test-Path $package) "$package wasn't built."

# Signed as the identity's publisher, with a certificate made here and
# trusted for package installs on this machine only.
$identity = Import-PowerShellDataFile "$root/helper/packaging/windows/identity.psd1"
$certificate = New-SelfSignedCertificate -Type Custom -Subject $identity.Publisher `
  -KeyUsage DigitalSignature -CertStoreLocation Cert:\CurrentUser\My `
  -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
$cer = Join-Path $work 'test.cer'
Export-Certificate -Cert $certificate -FilePath $cer | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople | Out-Null
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
  Sort-Object { [version]$_.Directory.Parent.Name } | Select-Object -Last 1
& $signtool.FullName sign /fd SHA256 /sha1 $certificate.Thumbprint /s My $package | Out-Host
Check ($LASTEXITCODE -eq 0) 'signtool failed.'

Add-AppxPackage $package
$installed = Get-AppxPackage -Name $identity.Name
Check ($null -ne $installed) "$($identity.Name) isn't installed."
Write-Host "Installed $($installed.PackageFullName) from $($installed.InstallLocation)"
$inside = Join-Path $installed.InstallLocation 'keyseal.exe'
Check ((Get-FileHash $inside).Hash -eq (Get-FileHash $built).Hash) 'The packaged exe differs from the build.'

# The execution alias, as a terminal finds it.
$alias = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\keyseal.exe'
Check (Test-Path $alias) "The execution alias $alias is missing."

# Runs the alias, piped so PowerShell waits for the GUI-subsystem exe and
# sees its output and stderr. Returns the exit code and the text.
function Keyseal {
  $ErrorActionPreference = 'Continue'
  $output = & $alias @args 2>&1 | Out-String
  Write-Host "keyseal $args exited with ${LASTEXITCODE}:`n$output"
  @($LASTEXITCODE, $output.Trim())
}

try {
  $code, $text = Keyseal --version
  Check ($code -eq 0 -and $text -eq "keyseal $version") "The alias printed $text."

  # A vendor driver outside the package, as a token's driver installs.
  $env:KEYSEAL_PKCS11_MODULE = 'C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll'
  $code, $text = Keyseal doctor
  Remove-Item Env:KEYSEAL_PKCS11_MODULE
  Check ($text -match 'Installed from the Microsoft Store') 'doctor did not run inside the package.'
  $tried = "  $([regex]::Escape('C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll')) \[[^\]]+\]: No token or smart card is plugged in\."
  Check ($text -match $tried) 'OpenSC did not load inside the package.'

  $code, $text = Keyseal update
  Check ($code -eq 0 -and $text -eq 'The Microsoft Store keeps this KeySeal up to date.') "keyseal update said $text."
  foreach ($command in 'install', 'uninstall') {
    $code, $text = Keyseal $command
    Check ($code -ne 0 -and $text -match 'error: The Microsoft Store installs and removes this KeySeal\.') `
      "keyseal $command exited with ${code}: $text"
  }
  Check (-not (Test-Path (Join-Path $env:LOCALAPPDATA 'keyseal'))) 'keyseal install copied the helper.'

  # Writes to %APPDATA% land in the package's folder.
  $log = Join-Path $env:LOCALAPPDATA "Packages\$($installed.PackageFamilyName)\LocalCache\Roaming\keyseal\keyseal.log"
  function Logged($text) { (Test-Path $log) -and (Get-Content -Raw $log).Contains($text) }
  Start-Process 'keyseal://sign?job=not-a-job'
  foreach ($try in 1..60) {
    if (Logged 'Job started.') { break }
    Start-Sleep 1
  }
  $started = Get-Process keyseal -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $inside }
  Check ($null -ne $started) 'The link did not start the packaged helper.'
  # The job logs its error once the signer closes the error window.
  $damaged = 'error: The KeySeal link is damaged'
  foreach ($try in 1..30) {
    if (Logged $damaged) { break }
    $started | ForEach-Object { [void]$_.CloseMainWindow() }
    Start-Sleep 1
  }
  if (Test-Path $log) { Write-Host "keyseal.log:`n$(Get-Content -Raw $log)" }
  Check (Logged $damaged) "The packaged helper did not log the damaged link to $log."
} finally {
  Get-Process keyseal -ErrorAction SilentlyContinue | Stop-Process -Force
}

Remove-AppxPackage $installed.PackageFullName
Check ($null -eq (Get-AppxPackage -Name $identity.Name)) 'The package is still installed.'
Check (-not (Test-Path $alias)) 'The execution alias is still there.'
Write-Host 'Packaged, installed, checked and uninstalled.'
