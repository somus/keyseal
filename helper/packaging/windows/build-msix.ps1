# Builds the unsigned MSIX package for the Microsoft Store from a release
# keyseal.exe: lays out the exe, the notices, the logos and the manifest
# filled in from identity.psd1, then packs it with makeappx from the
# Windows SDK. Prints the package's path.
#
#   build-msix.ps1 <keyseal.exe> <THIRD-PARTY-NOTICES.txt> <version> <out-dir>
#
# Windows only. The Store signs the package; CI signs a copy with a
# throwaway certificate to install it.
param(
  [Parameter(Mandatory)] [string] $Exe,
  [Parameter(Mandatory)] [string] $Notices,
  [Parameter(Mandatory)] [string] $Version,
  [Parameter(Mandatory)] [string] $OutDir
)
$ErrorActionPreference = 'Stop'

# The Store wants four parts, the first not 0 and the last 0, and the
# helper's versions start at 0: major.minor.patch becomes
# (major+1).minor.patch.0, here and nowhere else. A prerelease suffix is
# dropped.
if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)') { throw "$Version isn't a version." }
$packageVersion = '{0}.{1}.{2}.0' -f ([int]$Matches[1] + 1), $Matches[2], $Matches[3]

$windows = $PSScriptRoot
$identity = Import-PowerShellDataFile (Join-Path $windows 'identity.psd1')
$manifest = Get-Content -Raw (Join-Path $windows 'AppxManifest.xml')
$values = @{
  NAME                   = $identity.Name
  PUBLISHER              = $identity.Publisher
  PUBLISHER_DISPLAY_NAME = $identity.PublisherDisplayName
  VERSION                = $packageVersion
}
foreach ($key in $values.Keys) {
  $manifest = $manifest.Replace("{{$key}}", [System.Security.SecurityElement]::Escape($values[$key]))
}

$layout = Join-Path ([System.IO.Path]::GetTempPath()) "keyseal-msix-$PID"
Remove-Item -Recurse -Force $layout -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$layout/assets" | Out-Null
Copy-Item $Exe "$layout/keyseal.exe"
Copy-Item $Notices "$layout/THIRD-PARTY-NOTICES.txt"
Copy-Item "$windows/assets/*.png" "$layout/assets/"
[System.IO.File]::WriteAllText("$layout/AppxManifest.xml", $manifest)

# The newest SDK on the machine.
$makeappx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" |
  Sort-Object { [version]$_.Directory.Parent.Name } | Select-Object -Last 1
if (-not $makeappx) { throw 'makeappx.exe from the Windows SDK is missing.' }

New-Item -ItemType Directory -Force $OutDir | Out-Null
$package = Join-Path (Resolve-Path $OutDir) "keyseal-helper-$Version-windows-x64.msix"
& $makeappx.FullName pack /o /d $layout /p $package | Out-Host
$status = $LASTEXITCODE
Remove-Item -Recurse -Force $layout
if ($status -ne 0) { throw "makeappx failed ($status)." }
$package
