# プリンター内の情報

{{#include ../../banners/hacktricks-training.md}}

LDAP credentialsを保存したプリンターは、サーバー設定を変更し、不正なエンドポイントに認証させることで、それらを漏えいする可能性があります。<sup>[[2]](#references)</sup> 結果はbind方式によって異なります。保護されていないsimple bindではパスワードが漏えいしますが、SASL challenge-response bindでは平文のパスワードは漏えいしません。<sup>[[8]](#references)</sup> [LDAP authentication and transport security](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks)を参照してください。

また、複数のプリンターには**ユーザー名を含むログ**が保存されていたり、Domain Controllerから**すべてのユーザー名をダウンロード**できたりすることがあります。

このような**機密情報**と、一般的な**セキュリティ対策の不足**により、プリンターは攻撃者にとって非常に興味深い標的です。

このトピックについては、次の入門ブログを参照してください。

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## プリンターの設定

- **場所**: LDAPサーバーのリストは通常、Webインターフェースにあります（例: *Network ➜ LDAP Setting ➜ Setting Up LDAP*）。
- **動作**: 多くの組み込みWebサーバーでは、**credentialsを再入力せずに**LDAPサーバーを変更できます（利便性のための機能 → セキュリティリスク）。
- **Exploit**: LDAPサーバーのアドレスを攻撃者が制御するホストにリダイレクトし、*Test Connection* / *Address Book Sync*ボタンを使って、プリンターから自分のホストにbindさせます。

---

## Credentialsの取得

### Method 1 – Netcatリスナー

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

単純な BindRequest では、サーバーが後でログインを拒否した場合でも、BER stream に bind DN と password が露出する可能性があります。匿名 lookup や SASL negotiation だけでは、保存された password は露出しません。<sup>[[8]](#references)</sup>

636/3269 で `nc` の listener を立てても、LDAP bind ではなく TLS handshake が見えるだけです。LDAPS には TLS 対応の endpoint が必要です。証明書の検証だけでは、プリンターが変更された hostname を受け入れ、新しい endpoint がその hostname に対する有効な証明書を持っている場合、pass-back を防げません。クライアントは、保存された credential の送信先として許可するサーバーも制限する必要があります。<sup>[[8]](#references)</sup>

### Method 2 – Full Rogue LDAP server（推奨）

プリンターは、bind を試みる前に有効な LDAP response を要求する場合があります。<sup>[[10]](#references)</sup> Full LDAP server でこの予備的なやり取りに対応できますが、強力な SASL mechanism または意図された TLS server に pinning されたクライアントに password を明かさせることはできません。<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

lookupは接続の証拠として扱い、passwordが漏えいした証明とは見なさないでください。passwordが露出するのは、クライアントがpasswordを含む平文bindを送信した場合のみです。実際のbindメカニズムとTLSの状態を確認してください。<sup>[[8]](#references)</sup>

> 💡  Responderには、rogue LDAPおよびSMB認証サービスが含まれています。単純なLDAP bindでは設定済みpasswordが露出する可能性がありますが、NTLM認証で生成されるのはchallenge-responseデータです。どちらもclear-text passwordとして説明しないでください。

### SASLメカニズムの選択

一部のプリンターのLDAPクライアントは、LDAPサーバーが通知するメカニズムから選択します。<sup>[[8]](#references)[[10]](#references)</sup> 調査によると、通知された平文SASLメカニズムを受け入れるクライアントは、通常のNTLMネゴシエーションならchallenge-responseデータしか得られないところで、passwordを送信する可能性があります。<sup>[[9]](#references)[[10]](#references)</sup> これは**クライアントポリシーの不備**であり、すべてのSASL bindに当てはまる性質ではありません。より強力なメカニズムを要求するクライアントや、意図したTLSサーバーをピン留めするクライアントなら、代わりに接続を拒否するはずです。<sup>[[8]](#references)</sup> OpenLDAPでは、平文に対応するSASLメカニズムはデフォルトで無効になっているため、標準状態のデーモンを使っても、この挙動がプリンターに存在する証明にはなりません。<sup>[[11]](#references)</sup>

---

## 最近のPass-Back脆弱性（2024-2025）

Pass-Backは理論上の問題ではありません。ベンダーは2024年と2025年にも、この攻撃クラスを正確に説明するアドバイザリを公開し続けています。

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFPのファームウェア≤ 57.69.91では、認証済みの管理者（またはデフォルトの認証情報が変更されていない場合は誰でも）が、次の操作を実行できました。

* **CVE-2024-12510 – LDAP pass-back**: LDAPサーバーのアドレスを変更してlookupを実行すると、デバイスが設定済みのWindows認証情報を攻撃者が管理するホストにleakする。
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder*の宛先を介した同様の問題で、NetNTLMv2またはFTPの平文認証情報がleakする。<sup>[[2]](#references)</sup>

次のような単純なlistenerを使えます。

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

または不正な SMB server（`impacket-smbserver`）を用意するだけで、認証情報を収集できます。  

### Canon imageRUNNER / imageCLASS – 2025年5月20日のアドバイザリ

Canonは、数十のレーザーおよびMFP製品ラインにおける **SMTP/LDAP pass-back** の脆弱性を確認しました。管理者アクセス権を持つ攻撃者はサーバー設定を変更し、LDAP **または** SMTPに保存された認証情報を取得できます（多くの組織では、スキャンしてメールを送信するために特権アカウントを使用しています）。<sup>[[3]](#references)</sup>

ベンダーのガイダンスでは、次の対策を明確に推奨しています。

1. パッチ適用済みファームウェアが利用可能になり次第、更新する。
2. 強力で一意の管理者パスワードを使用する。
3. プリンター連携に特権ADアカウントを使用しない。

---

### Brother製デバイスおよびOEM製品 – シリアル番号から管理者アクセスを取得し、サービス認証情報を窃取

2025年の協調的な脆弱性開示により、影響を受けるBrother製デバイスで特に有用な攻撃チェーンが実証されました。脆弱性の一部はOEMモデルにも影響するため、ベンダーのアドバイザリで正確なモデルを確認してください。脆弱なファームウェアでは、認証されていない攻撃者がHTTP/HTTPS/IPP経由でデバイスのシリアル番号を取得できます。シリアル番号は、SNMPやPJLなどの管理プロトコルからも取得できる場合があります。工場出荷時のパスワードが変更されていない場合、シリアル番号から管理者パスワードを特定できます。認証後、別のpass-back脆弱性であるCVE-2024-51984により、LDAPやFTPなどの設定済み外部サービスのパスワードが平文で露呈し、プリンターの管理アクセスが再利用可能なネットワーク認証情報につながります。ファームウェアの更新でサービスパスワードの漏えいは修正されますが、既に製造されたデバイスでは、シリアル番号から導出される初期管理者パスワードを引き続き変更する必要があります。<sup>[[6]](#references)</sup>

現行のMetasploitには、HTTP、SNMP、またはPJL経由でシリアル番号を特定し、初期パスワード候補を生成して、オプションでWebコンソールに対して検証するauxiliary moduleが含まれています。`DiscoverSerialVia=AUTO`は、サポートされている検出方法を試します。資産台帳にシリアル番号が記録されている場合は、代わりに`TargetSerial`を指定してください。<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

結果は、許可された資産の検証にのみ使用してください。パスワードが機能するかどうかは正確なモデルに依存し、特に、工場出荷時の管理者パスワードがすでに変更されているかどうかが重要です。<sup>[[6]](#references)[[7]](#references)</sup>

---

## 自動列挙 / Exploitation Tools

| ツール | 目的 | 例 |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL の悪用、ファイルシステムへのアクセス、デフォルト認証情報の確認、*SNMP の探索*。[PJL assessment](../../network-services-pentesting/9100-pjl.md) を参照 | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS 経由で設定情報（アドレス帳や LDAP 認証情報を含む）を収集 | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | 不正な認証サービスを実行し、SMB コールバックから NetNTLM を取得 / リレー | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | シリアル番号を特定し、工場出荷時の管理者パスワード候補を導出して、Web コンソールへのアクセスを検証 | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening & Detection

1. **速やかに MFP にパッチを適用 / firmware-update する**（ベンダーの PSIRT 公告を確認）。
2. **工場出荷時の管理者パスワードを変更する** – firmware だけでは、以前に製造された影響対象の Brother / OEM デバイスに設定された、シリアル番号から導出される初期パスワードは削除されません。<sup>[[6]](#references)</sup>
3. **サービスアカウントに最小権限を適用する** – LDAP/SMB/SMTP で Domain Admin を使用せず、対象 OU の範囲を *読み取り専用* に制限する。
4. **管理アクセスを制限する** – プリンターの Web/IPP/SNMP インターフェースを管理 VLAN 内に配置するか、ACL/VPN の背後に置く。
5. **プリンターの外向き通信を制限する** – 各デバイスが、想定される DC/LDAP、メール、DNS/NTP、印刷、スキャンファイルの宛先にのみ接続できるようにする。Pass-back には、攻撃者が選択したエンドポイントへのコールバックが必要です。
6. **未使用のプロトコルを無効にする** – FTP、Telnet、raw-9100、古い SSL 暗号スイート。
7. **監査ログを有効にする** – 一部のデバイスでは LDAP/SMTP の失敗を syslog に記録できます。不審な bind を関連付けて確認してください。
8. **認証先を監視する** – プリンターが許可リスト外のホストに LDAP、SMB、SMTP、FTP 接続を開始した場合、特に管理者ログインや設定変更の直後はアラートを発報する。
9. **SNMPv3 を使用するか、SNMP を無効にする** – community `public` は、デバイスやシリアル番号の情報を漏えいさせることがよくあります。

---



---



## References

- [1] [単なるプリンターなのに……最悪、何が起こるというのか？](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 多機能プリンター：Pass-Back Attack の脆弱性（修正済み）](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004：業務用プリンター、オフィス / 小規模オフィス向け多機能プリンター、レーザープリンターの脆弱性緩和 / 修正](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Netcat を使用してプリンター経由でドメイン認証情報を取得する](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [ペネトレーションテスト中に多機能プリンターを悪用する](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [複数の Brother デバイス：複数の脆弱性（修正済み）](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit：Brother のデフォルト管理者認証バイパスモジュール](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – LDAP 認証方式とセキュリティメカニズム](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [LDAP passback Docker サーバー](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [LDAP pass back attack – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – SASL セキュリティプロパティ](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
