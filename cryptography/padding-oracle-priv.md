<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>


# CBC - Cipher Block Chaining

CBCモードでは、**前の暗号化されたブロックがIVとして使用**され、次のブロックとXORされます：

![CBC encryption](https://defuse.ca/images/cbc\_encryption.png)

CBCを復号するには、**逆の操作**が行われます：

![CBC decryption](https://defuse.ca/images/cbc\_decryption.png)

暗号化には**暗号化キー**と**IV**が必要です。

# メッセージのパディング

暗号化は**固定サイズのブロック**で行われるため、通常は**最後のブロック**にパディングが必要です。\
通常は**PKCS7**が使用され、ブロックを**完全にするために必要なバイト数**を**繰り返す**パディングが生成されます。たとえば、最後のブロックが3バイト不足している場合、パディングは`\x03\x03\x03`になります。

**8バイトの2つのブロック**のさらなる例を見てみましょう：

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

最後の例では、**最後のブロックがいっぱいだったため、パディングだけで別のブロックが生成**されたことに注意してください。

# パディングオラクル

アプリケーションが暗号化されたデータを復号する場合、まずデータを復号し、その後パディングを削除します。パディングのクリーンアップ中に、**検出可能な動作が無効なパディングをトリガー**する場合、パディングオラクルの脆弱性があります。検出可能な動作は、**エラー**、**結果の欠如**、または**応答の遅延**などです。

この動作を検出すると、**暗号化されたデータを復号**し、さらに**任意のクリアテキストを暗号化**することができます。

## 悪用方法

この種の脆弱性を悪用するには、[https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster)を使用するか、単に以下の操作を行います。
```
sudo apt-get install padbuster
```
サイトのクッキーが脆弱かどうかをテストするために、以下の方法を試すことができます：

```plaintext
1. クッキーの暗号化方式を特定します。これは、Set-Cookieヘッダーの値やCookieの値から推測することができます。

2. クッキーの暗号化方式に関連するパディングオラクル攻撃を実行します。これにより、クッキーの暗号化に使用されるパディングスキームの脆弱性を検出することができます。

3. パディングオラクル攻撃によってクッキーの暗号化に使用されるパディングスキームが脆弱であることが判明した場合、攻撃者は暗号文を解読することができます。

4. 解読された暗号文を使用して、攻撃者はクッキーの値を変更したり、セッションを乗っ取ったりすることができます。

注意：パディングオラクル攻撃は合法的なテストの範囲内でのみ実施してください。悪意のある目的で使用することは違法です。
```

この方法を使用して、サイトのクッキーの脆弱性をテストすることができます。ただし、合法的なテストの範囲内でのみ使用してください。
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**エンコーディング0**は、**base64**が使用されていることを意味します（ただし、他のものも利用可能です。ヘルプメニューを確認してください）。

また、この脆弱性を悪用して新しいデータを暗号化することもできます。たとえば、クッキーの内容が「\_user=MyUsername\_」であるとします。その場合、それを「\_user=administrator\_」に変更してアプリケーション内で特権を昇格させることができます。`paduster`を使用して`-plaintext`パラメータを指定しても同様に行うことができます。
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
もしサイトが脆弱であれば、`padbuster`は自動的にパディングエラーが発生するタイミングを見つけようとしますが、**-error**パラメータを使用してエラーメッセージを指定することもできます。
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## 理論

要約すると、正しい値を推測して異なるパディングを作成するために使用できる値を推測することで、暗号化されたデータの復号化を開始することができます。その後、パディングオラクル攻撃は、1、2、3などの正しい値を推測して、終了から開始までのバイトを復号化し始めます。

![](<../.gitbook/assets/image (629) (1) (1).png>)

E0からE15までのバイトで形成される2つのブロックで構成される暗号化されたテキストがあると想像してください。最後のブロック（E8からE15）を復号化するために、ブロック暗号の復号化を通過することで、中間バイトI0からI15が生成されます。最後に、各中間バイトは前の暗号化されたバイト（E0からE7）とXORされます。したがって：

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

今、`C15`が`0x01`であるまで`E7`を変更することができます。これは正しいパディングでもあります。したがって、この場合は：`\x01 = I15 ^ E'7`

したがって、`E'7`を見つけると、`I15`を計算することができます：`I15 = 0x01 ^ E'7`

これにより、`C15`を計算することができます：`C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

`C15`がわかったので、今度はパディング`\x02\x02`をブルートフォースして`C14`を計算することができます。

このBFは前のものと同じくらい複雑です。`C14`が`0x02`と等しい`E'14`を生成する`E''15`を見つけることができます：`E''7 = \x02 ^ I15`なので、`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`と同じ手順を実行してC14を復号化します。

**暗号化されたテキスト全体を復号化するまで、このチェーンに従ってください。**

## 脆弱性の検出

アカウントを登録し、このアカウントでログインします。\
何度もログインしても常に同じクッキーが返される場合、アプリケーションにはおそらく何か問題があります。クッキーはログインするたびに一意であるべきです。クッキーが常に同じであれば、おそらく常に有効であり、無効にする方法はありません。

さて、クッキーを変更しようとすると、アプリケーションからエラーが返されることがわかります。\
ただし、パディングをブルートフォースする（たとえば、padbusterを使用する）と、別のユーザーに対して有効な別のクッキーを取得できます。このシナリオは、おそらくpadbusterに対して脆弱性がある可能性が高いです。

# 参考文献

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！**

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[NFT](https://opensea.io/collection/the-peass-family)のコレクション

- [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
