# Windows packaging

Release one ships Windows unsigned, as a per-user install with no installer
program:

- `keyseal-helper-<version>-windows-x64.zip` holds `keyseal.exe` and
  `install.cmd`. The user unzips it and double-clicks `install.cmd`, which
  runs `keyseal.exe install`: it copies `keyseal.exe` to `%LOCALAPPDATA%\keyseal`,
  removes the download mark (`Zone.Identifier`) from the copy, registers
  `keyseal://` under `HKCU\Software\Classes\keyseal`, adds a KeySeal
  shortcut to the Start menu that opens the settings, and adds KeySeal to
  Apps (Add or remove programs) under
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\KeySeal`.
  SmartScreen warns once, for the unsigned download. `install.cmd` waits
  for a key before closing its window; `install.cmd /quiet` doesn't, for an
  unattended install, and exits with `keyseal.exe install`'s exit code.
- Opening `keyseal.exe` without a link, from the Start menu or Explorer,
  opens the settings. From a terminal it prints the usage.
- `keyseal-helper-<version>-windows-x64.exe` is the bare binary, the update
  asset named in `keyseal-update.json`. Installed helpers download it
  themselves, so it carries no download mark.
- `keyseal uninstall`, or Uninstall in Apps, removes the registration, the
  shortcut, the Apps entry and the install folder. The running
  `keyseal.exe` can't delete itself, so a hidden PowerShell waits for it to
  exit and then deletes the helper's own files in
  `%LOCALAPPDATA%\keyseal` and the folder once it is empty.
- The exe carries version information whose FileDescription, KeySeal, is
  the name browsers show when a site opens a `keyseal://` link.

Code signing comes after release one through SignPath Foundation; see
`docs/code-signing-policy.md`. The release workflow has a marked TODO
where the signing request goes.
