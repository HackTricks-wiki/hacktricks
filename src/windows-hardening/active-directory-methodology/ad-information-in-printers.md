# プリンター内の情報

{{#include ../../banners/hacktricks-training.md}}

インターネット上には、LDAP を設定したプリンターにデフォルトまたは弱いログイン認証情報を残す危険性を**指摘する**ブログがいくつもあります。  \
これは、攻撃者が**プリンターを騙して不正な LDAP server に対して認証させ**（通常は `nc -vv -l -p 389` または `slapd -d 2` で十分です）、プリンターの**認証情報を平文で**取得できるためです。

また、多くのプリンターには**ユーザー名を含むログ**が保存されており、Domain Controller からすべてのユーザー名を**ダウンロード**できる場合もあります。

こうした**機密情報**と、一般的な**セキュリティの欠如**により、プリンターは攻撃者にとって非常に興味深い対象です。

このトピックに関する入門ブログ:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## プリンターの設定

- **場所**: LDAP server の一覧は通常、Web インターフェースにあります（例: *Network ➜ LDAP Setting ➜ Setting Up LDAP*）。
- **動作**: 多くの組み込み Web server では、認証情報を再入力せずに LDAP server を変更できます（使いやすさのための機能 → セキュリティリスク）。
- **悪用方法**: LDAP server のアドレスを攻撃者が管理するホストにリダイレクトし、*Test Connection* / *Address Book Sync* ボタンを使ってプリンターに自分の server への bind を強制します。

---

## 認証情報の取得

### 方法 1 – Netcat Listener

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

小型／旧型の MFP は、bind DN とパスワードが raw BER stream 上で可視の単純な *simple-bind* を送信する場合があります。最新のデバイスは通常、最初に anonymous query を実行してから bind を試みるため、結果は異なります。<sup>[[1]](#references)</sup>

636/3269 で単純な `nc` listener を起動しても TLS ciphertext を受信するだけです。LDAPS のテストには TLS に対応した LDAP endpoint が必要であり、デバイスがサーバー証明書を正しく検証する場合、リダイレクトは失敗します。

### 方法 2 – 完全な Rogue LDAP server（推奨）

多くのデバイスは認証前に anonymous search を実行するため、実際の LDAP daemon を起動すると、はるかに確実な結果が得られます。<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

プリンターが検索を実行すると、デバッグ出力に平文の認証情報が表示されます。

> 💡 Responderには、偽装LDAPおよびSMB認証サービスが含まれています。単純なLDAP bindでは設定済みパスワードが漏えいする可能性があります。一方、NTLM認証で得られるのはチャレンジレスポンス情報です。どちらの場合も平文パスワードが得られるとは説明しないでください。

---

## 最近のPass-Back脆弱性（2024-2025）

Pass-backは*理論上の問題ではありません*。ベンダーは2024年から2025年にかけて、この攻撃クラスを正確に説明するアドバイザリを公開し続けています。

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFPのファームウェアバージョン57.69.91以下では、認証済みの管理者（またはデフォルトの認証情報が変更されていない場合は誰でも）が、次の操作を実行できました。

* **CVE-2024-12510 – LDAP pass-back**: LDAPサーバーアドレスを変更して検索を実行させると、デバイスから攻撃者が制御するホストへ設定済みのWindows認証情報が漏えいします。
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder*の宛先を使った同一の問題で、NetNTLMv2またはFTPの平文認証情報が漏えいします。<sup>[[2]](#references)</sup>

次のような単純なリスナーで対応できます。

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

または、不正な SMB server（`impacket-smbserver`）を用意すれば、認証情報を収集できます。  

### Canon imageRUNNER / imageCLASS – 2025年5月20日のアドバイザリ

Canonは、数十種類の Laser および MFP 製品ラインにおける **SMTP/LDAP pass-back** の脆弱性を確認しました。管理者アクセス権を持つ攻撃者は、サーバー設定を変更して、LDAP **または** SMTP の保存済み認証情報を取得できます（多くの組織では、スキャンした文書をメール送信するために、特権アカウントを使用しています）。<sup>[[3]](#references)</sup>

ベンダーのガイダンスでは、次の対策が明示的に推奨されています。

1. パッチ適用済みファームウェアが利用可能になり次第、更新する。
2. 強固で一意な管理者パスワードを使用する。
3. プリンター連携に特権 AD アカウントを使用しない。

---

### Brother デバイスおよび OEM 製品 – シリアル番号から管理者アクセスを取得し、サービス認証情報を入手

2025年の協調的な脆弱性開示により、影響を受ける Brother デバイスで特に有用な攻撃チェーンが実証されました。この脆弱性群の一部は OEM モデルにも影響するため、ベンダーのアドバイザリで正確なモデルを確認してください。脆弱なファームウェアでは、認証されていない攻撃者が HTTP/HTTPS/IPP 経由でデバイスのシリアル番号を取得できます。また、SNMP や PJL などの管理プロトコルからシリアル番号を取得できる場合もあります。初期パスワードが変更されていなければ、シリアル番号から管理者パスワードを確定的に導き出せます。認証後、別の pass-back の脆弱性 CVE-2024-51984 により、LDAP や FTP などの外部サービス用に設定されたパスワードが平文で漏えいし、プリンター管理アクセスが再利用可能なネットワーク認証情報の取得につながります。ファームウェア更新によりサービスパスワードの漏えいは修正されますが、すでに製造されたデバイスでは、シリアル番号から導かれる初期管理者パスワードを管理者が変更する必要があります。<sup>[[6]](#references)</sup>

現在の Metasploit には、HTTP、SNMP、または PJL 経由でシリアル番号を特定し、初期パスワードの候補を生成して、オプションで Web コンソールに対して検証する auxiliary module が含まれています。`DiscoverSerialVia=AUTO` は、サポートされている検出方法を順に試します。資産管理台帳にシリアル番号が記録されている場合は、代わりに `TargetSerial` を指定してください。<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

認可された資産の検証にのみ使用してください。パスワードが機能するかどうかは、正確なモデルと、特に工場出荷時の管理者パスワードがすでに変更されているかどうかに左右されます。<sup>[[6]](#references)[[7]](#references)</sup>

---

## 自動列挙 / Exploitation Tools

| Tool | 目的 | 例 |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL の悪用、ファイルシステムへのアクセス、デフォルト認証情報の確認、*SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS 経由で設定情報（アドレス帳や LDAP 認証情報を含む）を収集 | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | 不正な認証サービスを実行し、SMB コールバックから NetNTLM を取得 / リレー | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | シリアル番号を特定し、工場出荷時の管理者パスワード候補を導出して、Web コンソールへのアクセスを検証 | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## ハードニングと検知

1. **パッチ適用 / ファームウェア更新** – MFP に速やかに適用します（ベンダーの PSIRT 公報を確認してください）。
2. **工場出荷時の管理者パスワードを変更** – ファームウェアだけでは、すでに製造された該当する Brother / OEM デバイスのシリアル番号由来の初期パスワードは削除されません。<sup>[[6]](#references)</sup>
3. **最小権限のサービスアカウント** – LDAP/SMB/SMTP に Domain Admin を使用せず、*読み取り専用*の OU スコープに制限します。
4. **管理アクセスを制限** – プリンターの Web/IPP/SNMP インターフェースを管理 VLAN または ACL/VPN の背後に配置します。
5. **プリンターの外向き通信を制限** – 各デバイスが、想定される DC/LDAP、メール、DNS/NTP、印刷、スキャンファイルの宛先とのみ通信できるようにします。Pass-back には、攻撃者が選択したエンドポイントへのコールバックが必要です。
6. **未使用のプロトコルを無効化** – FTP、Telnet、raw-9100、古い SSL 暗号スイート。
7. **監査ログを有効化** – LDAP/SMTP の失敗を syslog に記録できるデバイスもあります。予期しない bind を関連付けて確認します。
8. **認証先を監視** – プリンターが許可リスト外のホストへ LDAP、SMB、SMTP、FTP を開始した場合、特に管理ログインや設定変更の直後はアラートを出します。
9. **SNMPv3 を使用するか、SNMP を無効化** – community `public` はデバイス情報やシリアル番号を漏らすことがよくあります。

---



---

## References

- [1] [プリンターにすぎない…最悪何が起こる？](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 複合機：Pass-Back 攻撃の脆弱性（修正済み）](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 製造用プリンター、オフィス / 小規模オフィス向け複合機、レーザープリンターの脆弱性緩和 / 修正](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Netcat を使用してプリンター経由でドメイン認証情報を取得する](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [ペネトレーションテスト中に複合機を悪用する](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [複数の Brother デバイス：複数の脆弱性（修正済み）](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit：Brother のデフォルト管理者認証バイパスモジュール](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
