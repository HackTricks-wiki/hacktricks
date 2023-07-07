# AD CS アカウントの永続化

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricks で会社を宣伝**したいですか？または、**PEASS の最新バージョンにアクセスしたり、HackTricks を PDF でダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション

- [**公式の PEASS & HackTricks スワッグ**](https://peass.creator-spring.com)を手に入れましょう

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discord グループ**](https://discord.gg/hRep4RUj7f)または[**telegram グループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricks リポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud リポジトリ](https://github.com/carlospolop/hacktricks-cloud)**に PR を提出してください。

</details>

## 証明書を介したアクティブユーザーの資格情報窃取 - PERSIST1

ユーザーがドメイン認証を許可される証明書をリクエストできる場合、攻撃者はそれを**リクエスト**して**窃取**し、**永続化**することができます。

**`User`** テンプレートはそれを許可し、**デフォルトで**提供されます。ただし、無効になっている場合もあります。したがって、[**Certify**](https://github.com/GhostPack/Certify)を使用して永続化するための有効な証明書を見つけることができます。
```
Certify.exe find /clientauth
```
注意してください。**証明書は認証に使用**されることができます。ユーザーが**パスワードを変更**しても、証明書が**有効**である限り、そのユーザーとして認証されます。

**GUI**からは、`certmgr.msc`を使用するか、コマンドラインから`certreq.exe`を使用して証明書を要求することができます。

[**Certify**](https://github.com/GhostPack/Certify)を使用すると、次のコマンドを実行できます：
```
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
結果は、テキストブロック形式の **証明書** + **秘密鍵** `.pem` となります。
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
その証明書を使用するために、`.pfx` ファイルをターゲットにアップロードし、[**Rubeus**](https://github.com/GhostPack/Rubeus) を使用して登録されたユーザーの TGT を要求することができます。証明書の有効期間（デフォルトは1年）の間、TGT を要求することができます。
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
{% hint style="warning" %}
[**THEFT5**](certificate-theft.md#ntlm-credential-theft-via-pkinit-theft5)セクションで説明されている技術と組み合わせることで、攻撃者はアカウントのNTLMハッシュを持続的に取得することができます。攻撃者はこれを使用して**パス・ザ・ハッシュ**または**クラック**を行い、**平文のパスワード**を取得することができます。\
これは**LSASSに触れずに**行われる**長期的な資格情報の盗難**の代替手法であり、**昇格していない状態**から可能です。
{% endhint %}

## 証明書を使用したマシンの永続化 - PERSIST2

証明書テンプレートが**Domain Computers**を登録主体として許可している場合、攻撃者は**侵害されたシステムのマシンアカウントを登録**することができます。デフォルトの**`Machine`**テンプレートはこれらの特性に一致します。

攻撃者が侵害されたシステムで特権を昇格させると、攻撃者は**SYSTEM**アカウントを使用して、マシンアカウントに登録権限を付与する証明書テンプレートに登録することができます（詳細は[**THEFT3**](certificate-theft.md#machine-certificate-theft-via-dpapi-theft3)を参照）。

[**Certify**](https://github.com/GhostPack/Certify)を使用して、自動的にSYSTEMに昇格してマシンアカウントの証明書を収集することができます。
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
アクセス権を持つマシンアカウント証明書を使用すると、攻撃者はマシンアカウントとして**Kerberosに認証**することができます。**S4U2Self**を使用して、攻撃者は任意のホスト上の**Kerberosサービスチケット**（例：CIFS、HTTP、RPCSSなど）を任意のユーザーとして取得できます。

最終的に、これにより攻撃者はマシンの持続性手法を得ることができます。

## 証明書の更新によるアカウントの持続性 - PERSIST3

証明書テンプレートには、発行された証明書の使用期間を決定する**有効期間**と、**更新期間**（通常は6週間）があります。これは、証明書が**期限切れになる前の一定期間**で、アカウントが発行元の証明書機関から証明書を**更新できる**ウィンドウです。

攻撃者が窃盗または悪意のある登録を介してドメイン認証が可能な証明書を侵害した場合、攻撃者は証明書の有効期間中にADに**認証できます**。ただし、攻撃者は**期限切れになる前に証明書を更新**することができます。これは、**追加のチケット**の登録が要求されないようにする**拡張された持続性**アプローチとして機能し、CAサーバー自体に**アーティファクトを残す**可能性があります。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
