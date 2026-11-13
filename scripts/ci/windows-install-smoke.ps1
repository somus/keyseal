# Builds the helper, installs it with `keyseal install`, checks the
# keyseal:// registration, the Start menu shortcut, the Apps entry and the
# exe's version information, then uninstalls it with the installed copy, as
# Apps does, and checks that all of it goes, the install folder after its
# deferred removal too. Opens no window.
#
#   scripts/ci/windows-install-smoke.ps1
#
# Windows only. It changes the current user's registry and Start menu, so
# CI runs it on a throwaway runner.
$ErrorActionPreference = 'Stop'

function Check($condition, $message) {
  if (-not $condition) { throw $message }
}

# Piped, so PowerShell waits for the GUI-subsystem exe and sees its output.
function Keyseal($exe, $command) {
  $output = & $exe $command | Out-String
  Write-Host $output
  Check ($LASTEXITCODE -eq 0) "keyseal $command exited with $LASTEXITCODE."
  $output.Trim()
}

$root = Resolve-Path "$PSScriptRoot/../.."
Push-Location "$root/helper"
cargo build -p keyseal-helper
Check ($LASTEXITCODE -eq 0) 'The helper did not build.'
Pop-Location
$built = "$root/helper/target/debug/keyseal.exe"

$dir = Join-Path $env:LOCALAPPDATA 'keyseal'
$exe = Join-Path $dir 'keyseal.exe'
$protocol = 'HKCU:\Software\Classes\keyseal'
$apps = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\KeySeal'
$shortcut = Join-Path ([Environment]::GetFolderPath('Programs')) 'KeySeal.lnk'
Check (-not (Test-Path $dir)) "$dir exists before the install."

# Windows caches the name browsers show for an exe under its path, and a
# helper from before 0.4.0 left "keyseal" there. An install drops it, and
# so does the first start after an update, neither waiting for reg.exe.
$names = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey(
  'Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache')
$name = "$exe.FriendlyAppName"
function CheckNameForgotten($after) {
  foreach ($try in 1..50) {
    if ($null -eq $names.GetValue($name)) { return }
    Start-Sleep -Milliseconds 100
  }
  throw "The cached name is still there after $after."
}

$names.SetValue($name, 'keyseal')
Keyseal $built 'install' | Out-Null
CheckNameForgotten 'the install'
Check (Test-Path $exe) "$exe wasn't installed."
Check ((Get-ItemProperty $protocol).'URL Protocol' -eq '') 'keyseal:// is not a URL protocol.'
$open = (Get-ItemProperty "$protocol\shell\open\command").'(default)'
Check ($open -eq "`"$exe`" `"%1`"") "keyseal:// opens $open."

Check (Test-Path $shortcut) "$shortcut is missing."
$link = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcut)
Check ($link.TargetPath -eq $exe -and $link.Arguments -eq 'settings') `
  "The shortcut runs $($link.TargetPath) $($link.Arguments)."

$version = (Keyseal $exe '--version') -replace '^keyseal ', ''
Check ($version -match '^\d+\.\d+\.\d+') "keyseal --version printed $version."
$entry = Get-ItemProperty $apps
Check ($entry.DisplayName -eq 'KeySeal') "The Apps entry is named $($entry.DisplayName)."
Check ($entry.DisplayVersion -eq $version) "The Apps entry has version $($entry.DisplayVersion)."
Check ($entry.Publisher -eq 'KeySeal' -and $entry.DisplayIcon -eq $exe) 'The Apps entry has the wrong publisher or icon.'
Check ($entry.UninstallString -eq "`"$exe`" uninstall") "The Apps entry uninstalls with $($entry.UninstallString)."
Check ($entry.NoModify -eq 1 -and $entry.NoRepair -eq 1) 'The Apps entry offers modify or repair.'

# Browsers name the app from FileDescription.
$info = (Get-Item $exe).VersionInfo
Check ($info.FileDescription -eq 'KeySeal') "FileDescription is $($info.FileDescription)."
Check ($info.ProductVersion -eq $version) "ProductVersion is $($info.ProductVersion)."

# Started as an update starts the helper it has just installed: with a link
# and KEYSEAL_UPDATED. It registers itself again, which here restores what
# an update leaves stale and what an earlier version's install didn't add.
# Headless, so the link, which names no job, fails without a window.
$names.SetValue($name, 'keyseal')
Set-ItemProperty $apps DisplayVersion '0.0.0'
Remove-Item $shortcut
$env:KEYSEAL_UPDATED = '1'
$env:KEYSEAL_HEADLESS = '1'
& $exe 'keyseal://updated' | Out-Null
Check ($LASTEXITCODE -ne 0) 'A link that names no job was run.'
Remove-Item Env:KEYSEAL_UPDATED, Env:KEYSEAL_HEADLESS
CheckNameForgotten 'an update'
Check ((Get-ItemProperty $apps).DisplayVersion -eq $version) 'An update left the Apps entry at the old version.'
Check (Test-Path $shortcut) 'An update did not put the Start menu shortcut back.'

Keyseal $exe 'uninstall' | Out-Null
Check (-not (Test-Path $protocol)) "$protocol is still there."
Check (-not (Test-Path $apps)) "$apps is still there."
Check (-not (Test-Path $shortcut)) "$shortcut is still there."
foreach ($second in 1..30) {
  if (-not (Test-Path $dir)) { break }
  Start-Sleep 1
}
if (Test-Path $dir) { throw "$dir is still there: $(Get-ChildItem $dir -Name)" }
Write-Host 'Installed, checked and uninstalled.'
