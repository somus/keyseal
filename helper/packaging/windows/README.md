# Windows packaging

Release one ships Windows unsigned, as a per-user install with no installer
program:

- `keyseal-helper-<version>-windows-x64.zip` holds `keyseal.exe` and
  `install.cmd`. The user unzips it and double-clicks `install.cmd`, which
  runs `keyseal.exe install`: it copies `keyseal.exe` to `%LOCALAPPDATA%\keyseal`,
  removes the download mark (`Zone.Identifier`) from the copy, and registers
  `keyseal://` under `HKCU\Software\Classes\keyseal`. SmartScreen warns once,
  for the unsigned download.
- `keyseal-helper-<version>-windows-x64.exe` is the bare binary, the update
  asset named in `keyseal-update.json`. Installed helpers download it
  themselves, so it carries no download mark.
- `keyseal uninstall` removes the registration and the install folder.

Code signing comes after release one through SignPath Foundation; see
`docs/code-signing-policy.md`. The release workflow has a marked TODO
where the signing request goes.
