<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェックしてください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>


# CBC - Cipher Block Chaining

CBCモードでは、**前の暗号化されたブロックがIVとして使用され**、次のブロックとXORされます：

![CBC encryption](https://defuse.ca/images/cbc\_encryption.png)

CBCを復号するには、**逆の操作**が行われます：

![CBC decryption](https://defuse.ca/images/cbc\_decryption.png)

**暗号化キー**と**IV**の使用が必要であることに注意してください。

# メッセージパディング

暗号化は**固定サイズのブロック**で行われるため、通常、**最後のブロック**を完成させるために**パディング**が必要です。
通常は**PKCS7**が使用され、ブロックを完成させるために必要な**バイト数を繰り返す**パディングが生成されます。例えば、最後のブロックが3バイト不足している場合、パディングは`\x03\x03\x03`になります。

**8バイト長の2ブロック**の例をもっと見てみましょう：

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

最後の例では、**最後のブロックがいっぱいだったので、パディングのみで別のブロックが生成された**ことに注意してください。

# Padding Oracle

アプリケーションが暗号化されたデータを復号するとき、まずデータを復号し、次にパディングを削除します。パディングのクリーンアップ中に、**無効なパディングが検出可能な挙動を引き起こす**場合、**パディングオラクルの脆弱性**があります。検出可能な挙動には、**エラー**、**結果の欠如**、または**応答の遅延**が含まれます。

この挙動を検出した場合、暗号化されたデータを**復号する**ことができ、さらに任意の**クリアテキストを暗号化する**こともできます。

## どのように悪用するか

この種の脆弱性を悪用するには、[https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster)を使用するか、単に
```
sudo apt-get install padbuster
```
サイトのクッキーが脆弱かどうかをテストするために、次の方法を試すことができます：
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**エンコーディング0** は **base64** が使用されていることを意味します（他にも利用可能なものがあります。ヘルプメニューを確認してください）。

また、この脆弱性を悪用して新しいデータを暗号化することもできます。例えば、クッキーの内容が "**_**user=MyUsername**_**" だった場合、それを "\_user=administrator\_" に変更してアプリケーション内で権限を昇格させることができます。`paduster` を使用して -plaintext パラメータを指定することでこれを行うこともできます：
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
サイトが脆弱である場合、`padbuster`は自動的にパディングエラーが発生するタイミングを見つけようとしますが、**-error** パラメータを使用してエラーメッセージを指定することもできます。
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## 理論

**要約すると**、異なる**パディング**を作成するために使用できる正しい値を推測することから、暗号化されたデータの復号化を開始できます。次に、パディングオラクル攻撃は、**1、2、3などのパディングを作成する**正しい値が何かを推測しながら、最後から始めるバイトを復号化し始めます。

![](<../.gitbook/assets/image (629) (1) (1).png>)

**2ブロック**にわたって配置された暗号化されたテキストがあると想像してください。これは、**E0からE15**までのバイトで構成されています。\
**最後のブロック**（**E8**から**E15**）を**復号化**するために、全ブロックが「ブロック暗号復号」を通過し、**中間バイトI0からI15**を生成します。\
最終的に、各中間バイトは前の暗号化されたバイト（E0からE7）と**XOR**されます。したがって：

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

今、`E7`を変更して`C15`が`0x01`になるまで**修正することが可能**です。これも正しいパディングになります。したがって、この場合：`\x01 = I15 ^ E'7`

E'7を見つけることで、**I15を計算することが可能**です：`I15 = 0x01 ^ E'7`

これにより、**C15を計算することができます**：`C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

**C15**を知っていると、今度は`\x02\x02`のパディングをブルートフォースすることで**C14を計算することが可能**です。

このBFは、0x02の値を持つ`E''15`を計算できるため、前のものと同じくらい複雑です：`E''7 = \x02 ^ I15`。したがって、**`C14`が`0x02`に等しい** **`E'14`**を見つけるだけで済みます。\
その後、C14を復号化するために同じ手順を実行します：**`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**この連鎖を続けて、暗号化されたテキスト全体を復号化します。**

## 脆弱性の検出

アカウントを登録し、このアカウントでログインします。\
もし何度**ログインしても常に同じクッキー**を受け取る場合、アプリケーションに**何か問題**がある可能性が高いです。ログインするたびに**クッキーはユニークであるべき**です。クッキーが**常に同じ**場合、おそらく常に有効であり、**無効にする方法はありません**。

今、クッキーを**変更**してみると、アプリケーションから**エラー**が返されることがわかります。\
しかし、パディングをブルートフォースする（例えばpadbusterを使用）と、別のユーザーのための有効な別のクッキーを取得することができます。このシナリオは、padbusterに対して高い確率で脆弱であると考えられます。

# 参考文献

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください**。

</details>
