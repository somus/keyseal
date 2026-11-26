#!/usr/bin/env bash
# Builds the AUR package that helper/packaging/package-managers.sh wrote, as
# a user would with makepkg, installs it, checks that KeySeal runs and its
# desktop entry claims keyseal:// links, runs namcap, and removes it.
#
#   scripts/ci/package-managers-arch.sh <out dir> <version>
#
# Runs as root in an archlinux:base-devel container, which it changes, so CI
# runs it in a throwaway one.
set -euo pipefail

out="$1"
version="$2"

pacman -Syu --noconfirm --needed namcap desktop-file-utils
useradd -m builder
cp -r "$out/aur/keyseal-bin" /home/builder/
chown -R builder: /home/builder/keyseal-bin
cd /home/builder/keyseal-bin

su builder -c 'makepkg --printsrcinfo' >printed.SRCINFO
diff -u .SRCINFO printed.SRCINFO
echo '.SRCINFO matches makepkg --printsrcinfo.'
# The aarch64 source can't be built here; check that it downloads and
# matches its checksum.
sed 's/^CARCH=.*/CARCH="aarch64"/' /etc/makepkg.conf >/tmp/makepkg-aarch64.conf
su builder -c 'makepkg --config /tmp/makepkg-aarch64.conf --verifysource'
# makepkg checks the dependencies but installs none without sudo.
pacman -S --noconfirm --needed --asdeps glibc gcc-libs libxcb libxkbcommon libxkbcommon-x11 vulkan-icd-loader wayland hicolor-icon-theme
su builder -c 'makepkg --noconfirm'

package="$(ls keyseal-bin-"$version"-1-x86_64.pkg.tar.*)"
pacman -U --noconfirm "$package"
printed="$(keyseal --version)"
[ "$printed" = "keyseal $version" ] || {
  echo "The installed helper prints $printed." >&2
  exit 1
}
echo "Installed $printed."
desktop-file-validate /usr/share/applications/keyseal.desktop
grep -qx 'MimeType=x-scheme-handler/keyseal;' /usr/share/applications/keyseal.desktop
# desktop-file-utils' pacman hook updates the handler cache.
grep -q '^x-scheme-handler/keyseal=keyseal.desktop;' /usr/share/applications/mimeinfo.cache
echo 'The desktop entry handles keyseal:// links.'
pacman -Ql keyseal-bin

# namcap marks errors with E:, which fail the job; warnings are shown.
namcap PKGBUILD "$package" | tee namcap.txt
if grep -q ' E: ' namcap.txt; then exit 1; fi

pacman -R --noconfirm keyseal-bin
for file in /usr/bin/keyseal /usr/share/applications/keyseal.desktop; do
  if [ -e "$file" ]; then
    echo "$file is still there." >&2
    exit 1
  fi
done
if grep -q keyseal /usr/share/applications/mimeinfo.cache; then exit 1; fi
echo 'Removed keyseal-bin.'
