# Pickle Rick

## Pickle Rick

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* サイバーセキュリティ会社で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

![](../../.gitbook/assets/picklerick.gif)

このマシンは簡単なカテゴリに分類され、かなり簡単でした。

## 列挙

私は[**Legion**](https://github.com/carlospolop/legion)というツールを使用してマシンの列挙を開始しました：

![](<../../.gitbook/assets/image (79) (2).png>)

上記のように、2つのポートが開いています：80（**HTTP**）と22（**SSH**）

したがって、私はLegionを使用してHTTPサービスを列挙しました：

![](<../../.gitbook/assets/image (234).png>)

画像では、`robots.txt`に文字列`Wubbalubbadubdub`が含まれていることがわかります。

数秒後、`disearch`がすでに発見したものを確認しました：

![](<../../.gitbook/assets/image (235).png>)

![](<../../.gitbook/assets/image (236).png>)

そして、最後の画像で**ログイン**ページが発見されました。

ルートページのソースコードをチェックすると、ユーザー名が見つかりました：`R1ckRul3s`

![](<../../.gitbook/assets/image (237) (1).png>)

したがって、資格情報`R1ckRul3s:Wubbalubbadubdub`を使用してログインページにログインできます。

## ユーザー

これらの資格情報を使用すると、コマンドを実行できるポータルにアクセスできます：

![](<../../.gitbook/assets/image (241).png>)

catなどの一部のコマンドは許可されていませんが、grepなどを使用して最初の材料（フラグ）を読むことができます：

![](<../../.gitbook/assets/image (242).png>)

次に、次のコマンドを使用しました：

![](<../../.gitbook/assets/image (243) (1).png>)

リバースシェルを取得するために：

![](<../../.gitbook/assets/image (239) (1).png>)

**2番目の材料**は`/home/rick`にあります。

![](<../../.gitbook/assets/image (240).png>)

## ルート

ユーザー**www-dataはsudoとして何でも実行できます**：

![](<../../.gitbook/assets/image (238).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* サイバーセキュリティ会社で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
