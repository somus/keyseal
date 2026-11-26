# Installs KeySeal from the winget manifests and then from the Chocolatey
# package that helper/packaging/package-managers.sh wrote, checks each
# install the way scripts/ci/windows-install-smoke.ps1 does, uninstalls it
# with the same tool and checks that it is gone.
#
#   scripts/ci/package-managers-windows.ps1 <out dir> <version>
#
# Needs winget with local manifests enabled and Chocolatey. It changes the
# current user's registry and Start menu, so CI runs it on a throwaway
# runner.
param([string]$Out, [string]$Version)
$ErrorActionPreference = 'Stop'

function Check($condition, $message) {
  if (-not $condition) { throw $message }
}

$dir = Join-Path $env:LOCALAPPDATA 'keyseal'
$exe = Join-Path $dir 'keyseal.exe'
$protocol = 'HKCU:\Software\Classes\keyseal'
$apps = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\KeySeal'

function CheckInstalled($by) {
  Check (Test-Path $exe) "$by didn't install $exe."
  $open = (Get-ItemProperty "$protocol\shell\open\command").'(default)'
  Check ($open -eq "`"$exe`" `"%1`"") "After $by, keyseal:// opens $open."
  $entry = Get-ItemProperty $apps
  Check ($entry.DisplayName -eq 'KeySeal' -and $entry.DisplayVersion -eq $Version) `
    "After $by, Apps lists $($entry.DisplayName) $($entry.DisplayVersion)."
  # Piped, so PowerShell waits for the GUI-subsystem exe and sees its output.
  $printed = (& $exe --version | Out-String).Trim()
  Check ($printed -eq "keyseal $Version") "The installed helper prints $printed."
  Write-Host "$by installed $printed and registered keyseal://."
}

function CheckRemoved($by) {
  Check (-not (Test-Path $protocol)) "After $by, $protocol is still there."
  Check (-not (Test-Path $apps)) "After $by, $apps is still there."
  # The helper removes its folder once it has exited.
  foreach ($second in 1..30) {
    if (-not (Test-Path $dir)) { break }
    Start-Sleep 1
  }
  if (Test-Path $dir) { throw "After $by, $dir is still there: $(Get-ChildItem $dir -Name)" }
  Write-Host "$by removed KeySeal."
}

Check (-not (Test-Path $dir)) "$dir exists before the installs."

$manifest = Join-Path $Out "winget/manifests/k/KeySeal/KeySeal/$Version"
winget validate --manifest $manifest --disable-interactivity
Check ($LASTEXITCODE -eq 0) "winget validate exited with $LASTEXITCODE."
winget install --manifest $manifest --disable-interactivity --accept-source-agreements --accept-package-agreements
Check ($LASTEXITCODE -eq 0) "winget install exited with $LASTEXITCODE."
CheckInstalled 'winget'
$list = winget list --name KeySeal --disable-interactivity --accept-source-agreements | Out-String
Write-Host $list
Check ($list -match "KeySeal\s+\S+\s+$([regex]::Escape($Version))") "winget list doesn't show KeySeal $Version."
# Finds the install by the manifest's Apps entry and runs its uninstall.
winget uninstall --manifest $manifest --disable-interactivity --accept-source-agreements
Check ($LASTEXITCODE -eq 0) "winget uninstall exited with $LASTEXITCODE."
CheckRemoved 'winget'

$feed = Join-Path $env:RUNNER_TEMP 'choco-feed'
choco pack (Join-Path $Out 'chocolatey/keyseal/keyseal.nuspec') --out $feed
Check ($LASTEXITCODE -eq 0) "choco pack exited with $LASTEXITCODE."
choco install keyseal --source $feed --yes --no-progress
Check ($LASTEXITCODE -eq 0) "choco install exited with $LASTEXITCODE."
CheckInstalled 'choco'
Check (-not (Test-Path (Join-Path $env:ChocolateyInstall 'bin/keyseal.exe'))) 'Chocolatey shimmed the downloaded keyseal.exe.'
choco uninstall keyseal --yes --no-progress
Check ($LASTEXITCODE -eq 0) "choco uninstall exited with $LASTEXITCODE."
CheckRemoved 'choco'
