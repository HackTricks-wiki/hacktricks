# パディングオラクル

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**する
* **ハッキングトリックを共有するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください**

</details>

## CBC - Cipher Block Chaining

CBCモードでは、**前の暗号化されたブロックがIVとして使用**され、次のブロックとXORされます:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

CBCを復号するには、**逆の操作**が行われます:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

暗号化には**暗号化キー**と**IV**が必要です。

## メッセージパディング

暗号化は**固定サイズのブロック**で行われるため、通常は**最後のブロックを完了するためにパディングが必要**です。\
通常は**PKCS7**が使用され、パディングはブロックを**完了するために必要なバイト数を繰り返す**ように生成されます。たとえば、最後のブロックが3バイト不足している場合、パディングは`\x03\x03\x03`になります。

**長さ8バイトの2ブロック**のさらなる例を見てみましょう:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

最後の例では、**最後のブロックが完全だったため、別のブロックがパディングのみで生成**されたことに注意してください。

## パディングオラクル

アプリケーションが暗号化されたデータを復号化すると、まずデータを復号化し、その後パディングを削除します。パディングのクリーンアップ中に、**無効なパディングが検出可能な動作を引き起こす**と、**パディングオラクルの脆弱性**が発生します。検出可能な動作には、**エラー**、**結果の欠如**、または**応答の遅延**が含まれる可能性があります。

この動作を検出した場合、**暗号化されたデータを復号化**し、さらに**任意のクリアテキストを暗号化**することができます。

### 悪用方法

この種の脆弱性を悪用するには、[https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster)を使用するか、単に行います
```
sudo apt-get install padbuster
```
サイトのクッキーが脆弱かどうかをテストするためには、次のように試すことができます:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**エンコーディング0**は、**base64**が使用されていることを意味します（他にも利用可能なものがありますが、ヘルプメニューを確認してください）。

この脆弱性を悪用して新しいデータを暗号化することもできます。たとえば、クッキーの内容が "**_**user=MyUsername**_**" であるとします。その場合、"\_user=administrator\_" に変更してアプリケーション内で特権を昇格させることができます。`paduster`を使用して、-plaintext**パラメータを指定して行うこともできます。
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
もしサイトが脆弱性を持っている場合、`padbuster`は自動的にパディングエラーが発生するタイミングを見つけようとしますが、**-error**パラメータを使用してエラーメッセージを指定することもできます。
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
### 理論

**要約すると**、異なる**パディング**を作成するために使用できる正しい値を推測して、暗号化されたデータの復号化を開始できます。その後、パディングオラクル攻撃は、**1、2、3などのパディングを作成する正しい値を推測**して、最後から最初にバイトを復号化し始めます。

![](<../.gitbook/assets/image (561).png>)

**E0からE15**までのバイトで形成される**2つのブロック**を占める暗号化されたテキストがあると想像してください。\
**最後のブロック**（**E8**から**E15**）を**復号化**するために、ブロック暗号の復号化を通過すると、**中間バイトI0からI15**が生成されます。\
最後に、各中間バイトは前の暗号化されたバイト（E0からE7）と**XOR**されます。つまり：

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

今、`C15`が`0x01`になるまで`E7`を変更することが可能で、これも正しいパディングになります。したがって、この場合は：`\x01 = I15 ^ E'7`

したがって、`E'7`を見つけると、**I15を計算することが可能**です：`I15 = 0x01 ^ E'7`

これにより、**C15を計算**することが可能になります：`C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

**C15**を知っているので、**C14を計算**することが可能になりますが、この時はパディング`\x02\x02`をブルートフォースします。

このBFは前のものと同じくらい複雑です。0x02の値を持つ`E''15`を計算できるので、`E''7 = \x02 ^ I15`を見つけるだけで、**`C14が0x02に等しい`**`E'14`を見つける必要があります。\
その後、C14を復号化するために同じ手順を実行します：**`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**このチェーンに従って、暗号化されたテキスト全体を復号化します。**

### 脆弱性の検出

このアカウントで登録してログインします。\
**何度もログイン**しても**常に同じクッキー**を取得する場合、アプリケーションにはおそらく**何か問題**があります。ログインするたびに送信されるクッキーは**一意であるべき**です。クッキーが**常に同じ**であれば、おそらく常に有効で**無効にする方法はない**でしょう。

次に、**クッキーを変更**しようとすると、アプリケーションから**エラー**が返ってくることがわかります。\
ただし、パディングをBFすると（たとえばpadbusterを使用）、別のユーザーに対して有効な別のクッキーを取得できます。このシナリオはpadbusterに非常に脆弱性がある可能性が高いです。

### 参考文献

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>で**ゼロからヒーローまでAWSハッキングを学ぶ**</summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFT](https://opensea.io/collection/the-peass-family)コレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)をフォローする
* **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して、**ハッキングトリックを共有**する

</details>
