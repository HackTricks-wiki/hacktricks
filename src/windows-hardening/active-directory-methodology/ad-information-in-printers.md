# プリンター内の情報

{{#include ../../banners/hacktricks-training.md}}

Internet上には、プリンターをLDAPで設定したまま、**デフォルトまたは脆弱な**ログオン認証情報を使用することの危険性を**指摘する**ブログがいくつかあります。  \
これは、攻撃者が**プリンターを不正なLDAPサーバーに対して認証するよう誘導**できるためです（通常、`nc -vv -l -p 389` または `slapd -d 2` で十分です）。その結果、プリンターの**認証情報を平文で**取得できます。

また、多くのプリンターには**ユーザー名を含むログ**が保存されており、Domain Controllerから**すべてのユーザー名をダウンロード**できる場合もあります。

これらすべての**機密情報**と、一般的な**セキュリティ対策の不足**により、プリンターは攻撃者にとって非常に興味深い対象となります。

このトピックに関する入門ブログ:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## プリンターの設定

- **Location**: LDAPサーバーの一覧は通常、Webインターフェース（例: *Network ➜ LDAP Setting ➜ Setting Up LDAP*）にあります。
- **Behavior**: 多くの組み込みWebサーバーでは、**認証情報を再入力せずに**LDAPサーバーを変更できます（使いやすさのための機能 → セキュリティリスク）。
- **Exploit**: LDAPサーバーのアドレスを攻撃者が管理するホストにリダイレクトし、*Test Connection* / *Address Book Sync* ボタンを使用して、プリンターから自分のサーバーへbindさせます。

---

## 認証情報の取得

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
小型/旧型の MFP は、netcat でキャプチャ可能な単純な *simple-bind* を平文で送信する場合があります。最新のデバイスは通常、最初に匿名クエリを実行してから bind を試みるため、結果は異なります。<sup>[[1]](#references)</sup>

### 方法 2 – Full Rogue LDAP server（推奨）

多くのデバイスは認証する*前に*匿名検索を実行するため、実際の LDAP デーモンを立ち上げると、より信頼性の高い結果が得られます。<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
プリンターが lookup を実行すると、debug output に clear-text credentials が表示されます。

> 💡  `impacket/examples/ldapd.py`（Python rogue LDAP）や `Responder -w -r -f` を使って、LDAP/SMB 経由で NTLMv2 hashes を harvest することもできます。

---

## 最近の Pass-Back Vulnerabilities（2024-2025）

Pass-back は理論上の問題ではありません。2024/2025 年にも、vendor はこの攻撃種別を正確に説明する advisory を公開し続けています。

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Xerox VersaLink C70xx MFP の Firmware ≤ 57.69.91 では、認証済み admin（または default creds が残っている場合は誰でも）が以下を実行できました。

* **CVE-2024-12510 – LDAP pass-back**: LDAP server address を変更して lookup を trigger し、設定された Windows credentials を attacker-controlled host に leak させる。
* **CVE-2024-12511 – SMB/FTP pass-back**: *scan-to-folder* destinations 経由でも同じ問題が発生し、NetNTLMv2 または FTP clear-text creds が leak する。<sup>[[2]](#references)</sup>

次のような単純な listener を使用します：
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
または rogue SMB server（`impacket-smbserver`）だけで認証情報を収集できます。

### Canon imageRUNNER / imageCLASS – 2025年5月20日アドバイザリ

Canonは、数十種類のLaserおよびMFP製品ラインにおける **SMTP/LDAP pass-back** の脆弱性を確認しました。admin accessを持つ攻撃者はサーバー設定を変更し、LDAP **または** SMTPに保存された認証情報を取得できます（多くの組織では、scan-to-mailを許可するために特権アカウントを使用しています）。<sup>[[3]](#references)</sup>

ベンダーのガイダンスでは、以下を明示的に推奨しています。

1. 利用可能になり次第、patched firmwareに更新する。
2. 強力で一意のadmin passwordsを使用する。
3. プリンター統合に特権AD accountsを使用しない。

---

## 自動Enumeration / Exploitation Tools

| Tool | Purpose | Example |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | PostScript/PJL/PCL abuse、file-system access、default-creds check、*SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | HTTP/HTTPS経由で設定（address booksおよびLDAP credsを含む）を収集 | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | SMB/FTP pass-backからNetNTLM hashesをcaptureおよびrelay | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | clear-text bindsを受信する軽量なrogue LDAP service | `python ldapd.py -debug` |

---

## HardeningおよびDetection

1. MFPを速やかに**Patch / firmware-update**する（ベンダーのPSIRT bulletinsを確認）。
2. **Least-Privilege Service Accounts** – LDAP/SMB/SMTPにDomain Adminを決して使用せず、*read-only* OU scopesに制限する。
3. **Restrict Management Access** – printer web/IPP/SNMP interfacesをmanagement VLAN内、またはACL/VPNの背後に配置する。
4. **Disable Unused Protocols** – FTP、Telnet、raw-9100、古いSSL ciphersを無効化する。
5. **Enable Audit Logging** – 一部のデバイスではLDAP/SMTP failuresをsyslogに記録できるため、予期しないbindsを相関分析する。
6. 通常とは異なるsourceからの**Clear-Text LDAP binds**を監視する（プリンターは通常、DCsとのみ通信するはずです）。
7. **SNMPv3またはSNMPを無効化** – community `public`からdeviceおよびLDAP configがleakすることがよくあります。

---

## References

- [1] [It's just a printer… What's the worst that could happen?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 Multifunction Printer: Pass-Back Attack Vulnerabilities (Fixed)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Vulnerability Mitigation/Remediation for Production Printers, Office/Small Office Multifunction Printers and Laser Printers](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Obtaining Domain Credentials through a Printer with Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
