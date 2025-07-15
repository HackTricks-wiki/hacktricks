# プリンタの情報

{{#include ../../banners/hacktricks-training.md}}

インターネット上には、**デフォルト/弱い**ログイン資格情報でLDAPが設定されたプリンタの危険性を**強調する**ブログがいくつかあります。 \
これは、攻撃者が**プリンタを騙して不正なLDAPサーバーに対して認証させる**ことができるためです（通常、`nc -vv -l -p 389`または`slapd -d 2`で十分です）し、プリンタの**資格情報を平文でキャプチャ**することができます。

また、いくつかのプリンタには**ユーザー名を含むログ**があり、ドメインコントローラから**すべてのユーザー名をダウンロード**できる場合もあります。

これらの**機密情報**と一般的な**セキュリティの欠如**により、プリンタは攻撃者にとって非常に興味深いターゲットとなります。

このトピックに関するいくつかの入門ブログ：

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

---
## プリンタの設定

- **場所**: LDAPサーバーのリストは通常、ウェブインターフェースにあります（例：*ネットワーク ➜ LDAP設定 ➜ LDAPの設定*）。
- **動作**: 多くの組み込みウェブサーバーは、**資格情報を再入力せずにLDAPサーバーの変更**を許可します（使いやすさの機能 → セキュリティリスク）。
- **エクスプロイト**: LDAPサーバーのアドレスを攻撃者が制御するホストにリダイレクトし、*接続テスト* / *アドレス帳の同期*ボタンを使用してプリンタをあなたにバインドさせます。

---
## 資格情報のキャプチャ

### 方法1 – Netcatリスナー
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
小型/古いMFPは、netcatがキャプチャできるクリアテキストで単純な *simple-bind* を送信する場合があります。最新のデバイスは通常、最初に匿名クエリを実行し、その後にバインドを試みるため、結果は異なります。

### 方法2 – フルローグLDAPサーバー（推奨）

多くのデバイスが認証する前に匿名検索を発行するため、実際のLDAPデーモンを立ち上げることで、はるかに信頼性の高い結果が得られます：
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
プリンターがルックアップを実行すると、デバッグ出力に平文の認証情報が表示されます。

> 💡  `impacket/examples/ldapd.py`（PythonのロゲLDAP）や`Responder -w -r -f`を使用して、LDAP/SMB経由でNTLMv2ハッシュを収集することもできます。

---
## 最近のパスバック脆弱性 (2024-2025)

パスバックは*理論的な問題ではありません* – ベンダーは2024/2025年にこの攻撃クラスを正確に説明するアドバイザリーを発表し続けています。

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFPのファームウェア≤ 57.69.91は、認証された管理者（またはデフォルトの認証情報が残っている場合は誰でも）が以下を行うことを許可しました：

* **CVE-2024-12510 – LDAPパスバック**: LDAPサーバーアドレスを変更し、ルックアップをトリガーすることで、デバイスが構成されたWindows認証情報を攻撃者が制御するホストに漏洩させる。
* **CVE-2024-12511 – SMB/FTPパスバック**: *スキャン先フォルダー*の宛先を介して同様の問題が発生し、NetNTLMv2またはFTPの平文認証情報が漏洩する。

次のようなシンプルなリスナー：
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
or a rogue SMB server (`impacket-smbserver`) は、資格情報を収集するのに十分です。

### Canon imageRUNNER / imageCLASS – 2025年5月20日 警告

Canonは、数十のレーザーおよびMFP製品ラインにおける**SMTP/LDAPパスバック**の脆弱性を確認しました。管理者アクセスを持つ攻撃者は、サーバー設定を変更し、LDAP **または** SMTPの保存された資格情報を取得できます（多くの組織はスキャンからメールへの送信を許可するために特権アカウントを使用します）。

ベンダーのガイダンスは明示的に次のことを推奨しています：

1. 利用可能になり次第、パッチが適用されたファームウェアに更新すること。
2. 強力でユニークな管理者パスワードを使用すること。
3. プリンタ統合のために特権ADアカウントを避けること。

---
## 自動列挙 / 攻撃ツール

| ツール | 目的 | 例 |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCLの悪用、ファイルシステムアクセス、デフォルト資格情報のチェック、*SNMP発見* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS経由で設定を収集（アドレス帳やLDAP資格情報を含む） | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | SMB/FTPパスバックからNetNTLMハッシュをキャプチャおよび中継 | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | プレーンテキストバインドを受信する軽量のロゲLDAPサービス | `python ldapd.py -debug` |

---
## ハードニング & 検出

1. **パッチ / ファームウェア更新** MFPを迅速に行う（ベンダーのPSIRT公告を確認）。
2. **最小特権サービスアカウント** – LDAP/SMB/SMTPにドメイン管理者を使用しない; *読み取り専用* OUスコープに制限する。
3. **管理アクセスの制限** – プリンタのWeb/IPP/SNMPインターフェースを管理VLANに配置するか、ACL/VPNの背後に置く。
4. **未使用プロトコルの無効化** – FTP、Telnet、raw-9100、古いSSL暗号。
5. **監査ログの有効化** – 一部のデバイスはLDAP/SMTPの失敗をsyslogできる; 予期しないバインドを相関させる。
6. **異常なソースからのプレーンテキストLDAPバインドを監視**（プリンタは通常DCとだけ通信するべきです）。
7. **SNMPv3またはSNMPを無効化** – コミュニティ`public`はしばしばデバイスおよびLDAP設定を漏洩します。

---
## 参考文献

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)
- Rapid7. “Xerox VersaLink C7025 MFP Pass-Back Attack Vulnerabilities.” 2025年2月。
- Canon PSIRT. “レーザープリンタおよび小型オフィス多機能プリンタに対するSMTP/LDAPパスバックの脆弱性緩和。” 2025年5月。

{{#include ../../banners/hacktricks-training.md}}
