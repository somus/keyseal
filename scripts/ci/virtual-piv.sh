#!/usr/bin/env bash
# Puts a virtual PIV card in a macOS runner, which macOS's own PIV driver
# exposes through CryptoTokenKit, for the helper's keychain test:
#
#   scripts/ci/virtual-piv.sh <dir>
#
# PivApplet runs in jCardSim behind vsmartcard's vpcd reader driver, which
# com.apple.ifdreader loads from /etc/reader.conf. The card gets an RSA-2048
# key in slot 9c with a certificate asserting digitalSignature and
# nonRepudiation, from a throwaway CA, and is then re-inserted: macOS picks a
# token driver only when a card appears, by selecting the driver's AID, and
# the applet isn't installed until after that. Needs sudo, a JDK 11 in
# JAVA_HOME, Maven and Homebrew. The simulator's log is <dir>/jcardsim.log.
set -euo pipefail

dir="$1"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$dir"
cd "$dir"

# vsmartcard 0.11's macOS installer, checked against the SHA-256 of the
# release asset.
vsmartcard_sha256=db2b866cf94ff121750689cc051c3b571d4ee3afe419247673b36c0d497d083e
curl -fsSL -o vsmartcard.zip \
  https://github.com/frankmorgner/vsmartcard/releases/download/virtualsmartcard-0.11/virtualsmartcard-macos.zip
echo "$vsmartcard_sha256  vsmartcard.zip" | shasum -a 256 -c -
unzip -q vsmartcard.zip
hdiutil attach -nobrowse -readonly -mountpoint vsmartcard virtualsmartcard-0.11_osx.dmg >/dev/null
sudo installer -pkg vsmartcard/VirtualSmartCard-0.11_install.pkg -target / >/dev/null
hdiutil detach vsmartcard >/dev/null
bundle=/Library/VirtualSmartCard/usr/local/libexec/SmartCardServices/drivers/ifd-vpcd.bundle
printf 'FRIENDLYNAME "Virtual PCD"\nDEVICENAME   /dev/null:0x8C7B\nLIBPATH      %s\nCHANNELID    0x8C7B\n' "$bundle" |
  sudo tee /etc/reader.conf >/dev/null
sudo launchctl kickstart -k system/com.apple.ifdreader

# Sources at fixed commits: the Java Card SDK jCardSim compiles against, the
# jCardSim fork PivApplet was tested with (upstream jCardSim refuses
# PivApplet's chained PUT DATA), and PivApplet.
fetch() {
  git init -q "$1"
  git -C "$1" fetch -q --depth 1 "https://github.com/$2.git" "$3"
  git -C "$1" checkout -q FETCH_HEAD
}
fetch sdks martinpaljak/oracle_javacard_sdks 700ec80afdda210a0e62fb6a151a9cddc1acd244
fetch jcardsim arekinath/jcardsim 4c766cfb48c43507f9a30a1443e7214d2073a430
fetch pivapplet arekinath/PivApplet 5cb14a9e8d16e92fbad73dcad86a219a9210554f

export JC_CLASSIC_HOME="$PWD/sdks/jc305u4_kit"
python3 "$here/jcardsim-reinsert.py" jcardsim/src/main/java/com/licel/jcardsim/remote/VSmartCard.java
# install-file runs in initialize, which a single run resolves dependencies
# before.
(cd jcardsim && mvn -B -q initialize && mvn -B -q -DskipTests package)
jar=jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar

brew install -q ant opensc yubico-piv-tool
(cd pivapplet && ant -q preprocess >/dev/null)
mkdir -p pivapplet/bin
javac -nowarn -source 8 -target 8 -cp "$JC_CLASSIC_HOME/lib/api_classic.jar" -d pivapplet/bin \
  $(find pivapplet/src-gen -name '*.java') 2>/dev/null

java -noverify -cp "pivapplet/bin:$jar" com.licel.jcardsim.remote.VSmartCard pivapplet/test/jcardsim.cfg \
  >jcardsim.log 2>&1 &
reader='Virtual PCD(1)'
for _ in $(seq 30); do
  opensc-tool -l 2>/dev/null | grep -q "Yes .*$reader" && break
  sleep 1
done
# jCardSim's command that installs the applet, with PivApplet's parameters.
opensc-tool -r "$reader" -s '80 b8 00 00 12 0b a0 00 00 03 08 00 00 10 00 01 00 05 00 00 02 0F 0F 7f' >/dev/null

piv() { yubico-piv-tool -r "$reader" "$@"; }
piv -a generate -s 9c -A RSA2048 -o pub.pem
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -subj "/CN=KeySeal Test PIV CA" -days 2 -out ca.pem 2>/dev/null
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\n' >leaf.ext
openssl req -new -key ca.key -subj "/CN=KeySeal Virtual PIV Signer" -out leaf.csr
openssl x509 -req -in leaf.csr -force_pubkey pub.pem -CA ca.pem -CAkey ca.key -days 2 -extfile leaf.ext \
  -out leaf.pem 2>/dev/null
piv -P 123456 -a verify-pin -a import-certificate -s 9c -i leaf.pem
piv -a set-chuid -a set-ccc

# Re-insert the card (jcardsim-reinsert.py) and wait for macOS's PIV token.
nc localhost 8099 </dev/null
for _ in $(seq 30); do
  security list-smartcards 2>/dev/null | grep -q com.apple.pivtoken && break
  sleep 1
done
security list-smartcards | grep com.apple.pivtoken
