# Installs KeySeal from the winget manifests and then from the Chocolatey
# package that helper/packaging/package-managers.sh wrote, checks each
# install the way scripts/ci/windows-install-smoke.ps1 does, uninstalls it
# with the same tool and checks that it is gone.
#
#   scripts/ci/package-managers-windows.ps1 <out dir> <version> winget|choco
#
# Needs winget with local manifests enabled and Chocolatey. It changes the
# current user's registry and Start menu, so CI runs it on a throwaway
# runner.
param([string]$Out, [string]$Version, [string]$Tool)
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

# Runs a package manager command, and if it hasn't finished within
# $minutes, lists the processes it may be waiting on before failing.
function Run($minutes, $program, [string[]]$arguments) {
  $process = Start-Process $program $arguments -NoNewWindow -PassThru
  $null = $process.Handle
  if (-not $process.WaitForExit($minutes * 60000)) {
    Get-CimInstance Win32_Process |
      Where-Object { $_.Name -match 'keyseal|reg|powershell|winget|choco|AppInstaller|smartscreen|consent|WerFault' } |
      Format-Table ProcessId, ParentProcessId, Name, CommandLine -AutoSize -Wrap | Out-String -Width 400 | Write-Host
    Get-ChildItem $env:TEMP -Recurse -Filter keyseal.exe -ErrorAction SilentlyContinue | ForEach-Object {
      Write-Host $_.FullName
      Get-Content $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue | Write-Host
    }
    throw "$program $arguments didn't finish within $minutes minutes."
  }
  $process.WaitForExit()
  Check ($process.ExitCode -eq 0) "$program $arguments exited with $($process.ExitCode)."
}

Check (-not (Test-Path $dir)) "$dir exists before the install."

if ($Tool -eq 'winget') {
  $manifest = Join-Path $Out "winget/manifests/k/KeySeal/KeySeal/$Version"
  Run 2 winget validate, --manifest, $manifest, --disable-interactivity
  Run 5 winget install, --manifest, $manifest, --disable-interactivity, --accept-source-agreements, --accept-package-agreements
  CheckInstalled 'winget'
  $list = winget list --name KeySeal --exact --disable-interactivity --accept-source-agreements | Out-String
  Write-Host $list
  Check ($list -match "KeySeal\s+\S+\s+$([regex]::Escape($Version))") "winget list doesn't show KeySeal $Version."
  # A package installed from a local manifest is matched by its Apps entry,
  # whose key the manifest declares as ProductCode, not by the manifest.
  Run 5 winget uninstall, --product-code, KeySeal, --disable-interactivity, --accept-source-agreements
  CheckRemoved 'winget'
} elseif ($Tool -eq 'choco') {
  $feed = Join-Path $env:RUNNER_TEMP 'choco-feed'
  choco pack (Join-Path $Out 'chocolatey/keyseal/keyseal.nuspec') --out $feed
  Check ($LASTEXITCODE -eq 0) "choco pack exited with $LASTEXITCODE."
  Run 5 choco install, keyseal, --source, $feed, --yes, --no-progress
  CheckInstalled 'choco'
  Check (-not (Test-Path (Join-Path $env:ChocolateyInstall 'bin/keyseal.exe'))) 'Chocolatey shimmed the downloaded keyseal.exe.'
  Run 5 choco uninstall, keyseal, --yes, --no-progress
  CheckRemoved 'choco'
} else {
  throw "Name winget or choco, not $Tool."
}
