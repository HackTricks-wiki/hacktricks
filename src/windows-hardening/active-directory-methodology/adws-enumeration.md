# Active Directory Web Services (ADWS) Enumerazione e raccolta stealth

{{#include ../../banners/hacktricks-training.md}}

## Cos'è ADWS?

Active Directory Web Services (ADWS) è **abilitato di default su ogni Domain Controller a partire da Windows Server 2008 R2** e ascolta sulla porta TCP **9389**. Nonostante il nome, **non c'è HTTP coinvolto**. Invece, il servizio espone dati in stile LDAP tramite una pila di protocolli di framing proprietari .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Poiché il traffico è incapsulato all'interno di questi frame SOAP binari e viaggia su una porta non comune, **l'enumerazione tramite ADWS è molto meno probabile che venga ispezionata, filtrata o rilevata tramite signature rispetto al classico traffico LDAP/389 & 636**. Per gli operatori questo significa:

* Recon più stealth — i Blue team spesso si concentrano sulle query LDAP.
* Libertà di raccogliere da **host non-Windows (Linux, macOS)** effettuando tunneling di 9389/TCP attraverso un proxy SOCKS.
* Gli stessi dati ottenibili via LDAP (users, groups, ACLs, schema, ecc.) e la possibilità di eseguire **scritture** (per esempio `msDs-AllowedToActOnBehalfOfOtherIdentity` per **RBCD**).

Le interazioni ADWS sono implementate su WS-Enumeration: ogni query inizia con un messaggio `Enumerate` che definisce il filtro/attributi LDAP e restituisce un GUID `EnumerationContext`, seguito da uno o più messaggi `Pull` che trasmettono fino alla finestra di risultati definita dal server. I contesti scadono dopo ~30 minuti, quindi gli strumenti devono o impaginare i risultati o dividere i filtri (query per prefisso su CN) per evitare di perdere lo stato. Quando si richiedono security descriptor, specificare il controllo `LDAP_SERVER_SD_FLAGS_OID` per omettere le SACL; altrimenti ADWS semplicemente rimuove l'attributo `nTSecurityDescriptor` dalla sua risposta SOAP.

> NOTA: ADWS è usato anche da molti strumenti RSAT GUI/PowerShell, quindi il traffico può mescolarsi con attività amministrativa legittima.

## SoaPy – Client Python nativo

[SoaPy](https://github.com/logangoins/soapy) è una **riimplementazione completa dello stack di protocolli ADWS in puro Python**. Costruisce i frame NBFX/NBFSE/NNS/NMF byte-per-byte, permettendo la raccolta da sistemi Unix-like senza toccare il runtime .NET.

### Caratteristiche principali

* Supporta il **proxying tramite SOCKS** (utile per C2 implants).
* Filtri di ricerca granulare identici a LDAP `-q '(objectClass=user)'`.
* Operazioni **di scrittura** opzionali (`--set` / `--delete`).
* **Modalità output BOFHound** per ingestione diretta in BloodHound.
* Flag `--parse` per rendere più leggibili timestamp / `userAccountControl` quando è richiesta la leggibilità umana.

### Flag di raccolta mirata e operazioni di scrittura

SoaPy include switch curati che replicano i task di hunting LDAP più comuni su ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, oltre ai knob grezzi `--query` / `--filter` per pull personalizzati. Abbinali a primitive di scrittura come `--rbcd <source>` (imposta `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (staging SPN per Kerberoasting mirato) e `--asrep` (inverte `DONT_REQ_PREAUTH` in `userAccountControl`).

Esempio di ricerca SPN mirata che restituisce solo `samAccountName` e `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Usa lo stesso host e le stesse credenziali per weaponise immediatamente i findings: esegui il dump degli oggetti RBCD-capable con `--rbcds`, quindi applica `--rbcd 'WEBSRV01$' --account 'FILE01$'` per mettere in scena una Resource-Based Constrained Delegation chain (vedi [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) per il percorso completo di abuso).

### Installazione (host operatore)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump su ADWS (Linux/Windows)

* Fork di `ldapdomaindump` che sostituisce le query LDAP con chiamate ADWS su TCP/9389 per ridurre i LDAP-signature hits.
* Esegue un controllo iniziale di raggiungibilità sulla porta 9389 a meno che non venga passato `--force` (salta la sonda se le scansioni di porta sono rumorose/filtrate).
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

Simile a soapy, [sopa](https://github.com/Macmod/sopa) implementa lo stack del protocollo ADWS (MS-NNS + MC-NMF + SOAP) in Golang, esponendo flag da riga di comando per eseguire chiamate ADWS come:

* **Ricerca e recupero di oggetti** - `query` / `get`
* **Ciclo di vita degli oggetti** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Modifica degli attributi** - `attr [add|replace|delete]`
* **Gestione account** - `set-password` / `change-password`
* e altri come `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Raccolta ADWS ad alto volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) è un collector .NET che mantiene tutte le interazioni LDAP all'interno di ADWS e genera JSON compatibile con BloodHound v4. Costruisce una cache completa di `objectSid`, `objectGUID`, `distinguishedName` and `objectClass` una sola volta (`--buildcache`), poi la riutilizza per passaggi ad alto volume `--bhdump`, `--certdump` (ADCS), o `--dnsdump` (AD-integrated DNS) in modo che solo ~35 attributi critici lascino mai il DC. AutoSplit (`--autosplit --threshold <N>`) frammenta automaticamente le query per prefisso CN per rimanere sotto il timeout di EnumerationContext di 30 minuti nelle foreste di grandi dimensioni.

Flusso di lavoro tipico su una VM dell'operatore joinata al dominio:
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
Gli slot JSON esportati si integrano direttamente nei workflow SharpHound/BloodHound — vedi [BloodHound methodology](bloodhound.md) per idee sulla creazione di grafici downstream. AutoSplit rende SOAPHound resiliente su foreste con milioni di oggetti, mantenendo il numero di query inferiore rispetto agli snapshot in stile ADExplorer.

## Flusso stealth di raccolta AD

Il seguente workflow mostra come enumerare **oggetti del dominio e ADCS** tramite ADWS, convertirli in BloodHound JSON e cercare percorsi di attacco basati su certificati – il tutto da Linux:

1. **Tunnel 9389/TCP** dalla rete target alla tua macchina (es. via Chisel, Meterpreter, SSH dynamic port-forward, ecc.). Esporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` oppure usa i flag di SoaPy `--proxyHost/--proxyPort`.

2. **Raccogli l'oggetto radice del dominio:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Raccogliere oggetti relativi ad ADCS dalla Configuration NC:**
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
5. **Upload the ZIP** nella BloodHound GUI e esegui cypher queries come `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` per rivelare i percorsi di escalation dei certificati (ESC1, ESC8, ecc.).

### Scrittura di `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combina questo con `s4u2proxy`/`Rubeus /getticket` per una catena completa di **Resource-Based Constrained Delegation** (vedi [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Riepilogo strumenti

| Scopo | Strumento | Note |
|---------|------|-------|
| Enumerazione ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lettura/scrittura |
| Dump ADWS ad alto volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modalità BH/ADCS/DNS |
| Importazione per BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Converte i log di SoaPy/ldapsearch |
| Compromissione certificati | [Certipy](https://github.com/ly4k/Certipy) | Può essere instradato tramite lo stesso SOCKS |
| Enumerazione ADWS e modifiche agli oggetti | [sopa](https://github.com/Macmod/sopa) | Client generico per interfacciarsi con endpoint ADWS noti - consente enumerazione, creazione di oggetti, modifiche di attributi e cambi di password |

## Riferimenti

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
