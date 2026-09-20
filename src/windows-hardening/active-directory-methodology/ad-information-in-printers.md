# プリンター内の情報

{{#include ../../banners/hacktricks-training.md}}

インターネット上には、**LDAP をデフォルトまたは弱い**ログイン認証情報で設定したままプリンターを放置する危険性を**指摘する**ブログがいくつかあります。  \
これは、攻撃者が**プリンターを誘導して悪意のある LDAP サーバーに対して認証させる**ことができ（通常は `nc -vv -l -p 389` または `slapd -d 2` で十分です）、プリンターの**認証情報を平文で**取得できるためです。

また、複数のプリンターには**ユーザー名を含むログ**が保存されている場合があり、Domain Controller から**すべてのユーザー名をダウンロード**できることさえあります。

このような**機密情報**と、一般的な**セキュリティ不足**により、プリンターは攻撃者にとって非常に興味深い対象となります。

このトピックに関する入門ブログ:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## プリンターの設定

- **場所**: LDAP サーバーの一覧は通常、Web インターフェースにあります（例: *Network ➜ LDAP Setting ➜ Setting Up LDAP*）。
- **動作**: 多くの組み込み Web サーバーでは、**認証情報を再入力せずに** LDAP サーバーを変更できます（使いやすさのための機能 → セキュリティリスク）。
- **Exploit**: LDAP サーバーのアドレスを攻撃者が制御するホストにリダイレクトし、*Test Connection* / *Address Book Sync* ボタンを使用して、プリンターから自分のサーバーへ bind させます。

---

## 認証情報の取得

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```
小型／旧型のMFPは、bind DNとパスワードが生のBERストリーム上で可視化される単純な *simple-bind* を送信する場合があります。最新のデバイスは通常、最初に匿名クエリを実行してからbindを試行するため、結果は異なります。<sup>[[1]](#references)</sup>

636/3269で単純な`nc`リスナーを使用した場合、受信できるのはTLS ciphertextだけです。LDAPSのテストにはTLS対応のLDAPエンドポイントが必要であり、デバイスがサーバー証明書を正しく検証する場合、リダイレクトは失敗するはずです。

### 方法2 – Full Rogue LDAP server（推奨）

多くのデバイスは認証の**前に**匿名検索を実行するため、実際のLDAP daemonを立ち上げると、はるかに信頼性の高い結果が得られます。<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
プリンターが lookup を実行すると、debug output に clear-text の credentials が表示されます。

> 💡  Responder には rogue LDAP および SMB authentication services が含まれています。単純な LDAP bind では設定された password が露出する可能性がありますが、NTLM authentication では challenge-response material が生成されます。両方の結果を clear-text password として説明しないでください。

---

## Recent Pass-Back Vulnerabilities (2024-2025)

Pass-back は*理論上の問題ではありません* – vendors は 2024/2025 年にも、この attack class を正確に説明する advisories を公開し続けています。

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFPs の firmware ≤ 57.69.91 では、authenticated admin（または default creds が残っている場合は誰でも）が次の操作を実行できました。

* **CVE-2024-12510 – LDAP pass-back**: LDAP server address を変更して lookup を trigger すると、device が設定された Windows credentials を attacker-controlled host に leak する。
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder* destinations 経由でも同一の問題が発生し、NetNTLMv2 または FTP clear-text creds が leak する。<sup>[[2]](#references)</sup>

次のような単純な listener:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
または不正な SMB server（`impacket-smbserver`）だけでも、credentials を収集できます。

### Canon imageRUNNER / imageCLASS – 2025年5月20日付 Advisory

Canonは、数十種類の Laser & MFP product line における **SMTP/LDAP pass-back** の弱点を確認しました。admin access を持つ attacker は server configuration を変更し、LDAP **または** SMTP に保存された credentials を取得できます（多くの組織では、scan-to-mail を可能にするため privileged account を使用しています）。<sup>[[3]](#references)</sup>

vendor guidance では、以下を明示的に推奨しています。

1. 利用可能になり次第、patched firmware に更新する。
2. 強力で一意の admin password を使用する。
3. printer integration に privileged AD account を使用しない。

---

### Brother devices and OEM variants – serial-derived admin access to service credentials

2025年の coordinated disclosure により、影響を受ける Brother devices で特に有用な chain が実証されました。この vulnerability set の一部は OEM models にも影響するため、vendor advisory で正確な model を確認してください。unauthenticated attacker は、vulnerable firmware 上で HTTP/HTTPS/IPP 経由で device serial を取得できます。また、serial は SNMP や PJL などの management protocols 経由でも取得できる場合があります。factory password が変更されていなければ、serial から administrator password を決定論的に導出できます。認証後は、別の pass-back flaw である CVE-2024-51984 により、LDAP や FTP など、設定済みの external-service password が plaintext で露出し、printer-management access が再利用可能な network credentials になります。Firmware により service-password disclosure は修正されますが、すでに製造された devices では、serial-derived initial administrator password を operator が変更する必要があります。<sup>[[6]](#references)</sup>

Current Metasploit には、HTTP、SNMP、または PJL 経由で serial を検出し、候補となる initial password を生成し、必要に応じて web console に対して検証する auxiliary module が含まれています。`DiscoverSerialVia=AUTO` は対応する discovery path を試行します。asset inventory に serial がすでに登録されている場合は、代わりに `TargetSerial` を指定してください。<sup>[[7]](#references)</sup>
```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```
許可された asset の検証にのみ使用してください。パスワードが機能するかどうかは、正確なモデルと、特に工場出荷時の administrator password がすでに変更されているかどうかに依存します。<sup>[[6]](#references)[[7]](#references)</sup>

---

## Automated Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL の悪用、ファイルシステムへのアクセス、default-creds check、*SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS 経由で設定（address book と LDAP creds を含む）を収集 | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | 不正な authentication service を実行し、SMB callback から NetNTLM を取得・relay | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | serial を特定し、候補となる factory administrator password を導出して、web-console access を検証 | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening & Detection

1. **Patch / firmware-update** を MFP に速やかに適用する（vendor PSIRT bulletin を確認）。
2. **factory administrator password を変更する** – firmware だけでは、以前に製造された影響を受ける Brother/OEM device に残る serial 由来の初期 password は削除されません。<sup>[[6]](#references)</sup>
3. **Least-Privilege Service Accounts** – LDAP/SMB/SMTP に Domain Admin を決して使用せず、*read-only* の OU scope に制限する。
4. **Management Access を制限する** – printer の web/IPP/SNMP interface を management VLAN 内、または ACL/VPN の背後に配置する。
5. **printer egress を制限する** – 各 device が想定された DC/LDAP、mail、DNS/NTP、print、scan-file の宛先にのみ接続できるようにする。Pass-back には、attacker が選択した endpoint への callback が必要です。
6. **未使用の protocol を無効化する** – FTP、Telnet、raw-9100、古い SSL cipher。
7. **Audit Logging を有効化する** – 一部の device は LDAP/SMTP failure を syslog に記録できます。予期しない bind を関連付けて分析する。
8. **authentication destination を監視する** – printer が allowlist 外の host に LDAP、SMB、SMTP、または FTP を開始した場合に alert を発生させる。特に management login または configuration change の直後は注意する。
9. **SNMPv3 または SNMP を無効化する** – community `public` から device および serial 情報がしばしば leak します。

---



---

## References

- [1] [これは単なる printer… 最悪の場合、何が起こる可能性があるのか？](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Netcat を使用して Printer から Domain Credentials を取得する](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Penetration Test Engagement 中の Multifunction Printer の Exploitation](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Multiple Brother Devices: Multiple Vulnerabilities (FIXED)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: Brother default administrator authentication bypass module](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
