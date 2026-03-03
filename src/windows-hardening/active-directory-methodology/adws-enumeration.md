# Enumerazione e raccolta stealth di Active Directory Web Services (ADWS)

{{#include ../../banners/hacktricks-training.md}}

## Che cos'è ADWS?

Active Directory Web Services (ADWS) è **abilitato di default su ogni Domain Controller a partire da Windows Server 2008 R2** e ascolta sulla porta TCP **9389**. Nonostante il nome, **non viene utilizzato HTTP**. Invece, il servizio espone dati in stile LDAP tramite uno stack di protocolli di framing proprietari .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Poiché il traffico è incapsulato in questi frame SOAP binari e viaggia su una porta poco comune, **l'enumerazione tramite ADWS è molto meno probabile che venga ispezionata, filtrata o rilevata tramite signature rispetto al classico traffico LDAP/389 & 636**. Per gli operatori questo significa:

* Ricognizione più stealth – i Blue teams spesso si concentrano sulle query LDAP.
* Libertà di raccogliere da **host non-Windows (Linux, macOS)** tunnelando 9389/TCP attraverso un proxy SOCKS.
* Gli stessi dati che otterresti via LDAP (users, groups, ACLs, schema, etc.) e la possibilità di eseguire **scritture** (es. `msDs-AllowedToActOnBehalfOfOtherIdentity` per **RBCD**).

Le interazioni ADWS sono implementate su WS-Enumeration: ogni query inizia con un messaggio `Enumerate` che definisce il filtro/attributi LDAP e restituisce un GUID `EnumerationContext`, seguito da uno o più messaggi `Pull` che streammano fino alla finestra di risultati definita dal server. I contesti scadono dopo ~30 minuti, quindi gli strumenti devono fare paging dei risultati o suddividere i filtri (query prefix per CN) per evitare di perdere stato. Quando si richiedono i security descriptor, specificare il controllo `LDAP_SERVER_SD_FLAGS_OID` per omettere le SACLs, altrimenti ADWS semplicemente omette l'attributo `nTSecurityDescriptor` dalla sua risposta SOAP.

> NOTA: ADWS è anche usato da molti strumenti RSAT GUI/PowerShell, quindi il traffico può confondersi con attività amministrative legittime.

## SoaPy – Client Python nativo

[SoaPy](https://github.com/logangoins/soapy) è una **re-implementazione completa dello stack di protocolli ADWS in puro Python**. Costruisce i frame NBFX/NBFSE/NNS/NMF byte-per-byte, permettendo la raccolta da sistemi Unix-like senza usare il runtime .NET.

### Caratteristiche principali

* Supporta il **proxy tramite SOCKS** (utile dagli implant C2).
* Filtri di ricerca granulare identici a LDAP `-q '(objectClass=user)'`.
* Operazioni opzionali di **scrittura** ( `--set` / `--delete` ).
* Modalità di output **BOFHound** per ingestione diretta in BloodHound.
* Flag `--parse` per rendere più leggibili timestamps / `userAccountControl` quando è richiesta la leggibilità umana.

### Flag di raccolta mirata & operazioni di scrittura

SoaPy viene fornito con switch curati che replicano i task di hunting LDAP più comuni su ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, oltre ai comandi grezzi `--query` / `--filter` per pull personalizzati. Abbinali a primitive di scrittura come `--rbcd <source>` (imposta `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging per Kerberoasting mirato) e `--asrep` (inverte `DONT_REQ_PREAUTH` in `userAccountControl`).

Esempio di ricerca SPN mirata che ritorna solo `samAccountName` e `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Usa lo stesso host/credentials per weaponise immediatamente i findings: dump RBCD-capable objects con `--rbcds`, quindi applica `--rbcd 'WEBSRV01$' --account 'FILE01$'` per stage una Resource-Based Constrained Delegation chain (vedi [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) per l'intero abuse path).

### Installazione (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Sopa - Un client pratico per ADWS in Golang

Similarly as soapy, [sopa](https://github.com/Macmod/sopa) implements the ADWS protocol stack (MS-NNS + MC-NMF + SOAP) in Golang, exposing command-line flags to issue ADWS calls such as:

* **Ricerca e recupero di oggetti** - `query` / `get`
* **Ciclo di vita degli oggetti** - `create [user|computer|group|ou|container|custom]` and `delete`
* **Modifica attributi** - `attr [add|replace|delete]`
* **Gestione account** - `set-password` / `change-password`
* and others such as `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, etc.

## SOAPHound – Raccolta ADWS ad alto volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) è un collector .NET che mantiene tutte le interazioni LDAP all'interno di ADWS e produce JSON compatibile con BloodHound v4. Costruisce una cache completa di `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` una sola volta (`--buildcache`), poi la riutilizza per passate ad alto volume come `--bhdump`, `--certdump` (ADCS), o `--dnsdump` (AD-integrated DNS), così solo ~35 attributi critici lasciano mai il DC. AutoSplit (`--autosplit --threshold <N>`) suddivide automaticamente le query per prefisso CN per restare al di sotto del timeout di EnumerationContext di 30 minuti nelle foreste di grandi dimensioni.

Tipico flusso di lavoro su una VM dell'operatore membro del dominio:
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
Gli slot JSON esportati si inseriscono direttamente nei workflow SharpHound/BloodHound — vedi [BloodHound methodology](bloodhound.md) per idee sulla visualizzazione a valle. AutoSplit rende SOAPHound resiliente su foreste con milioni di oggetti mantenendo il numero di query inferiore rispetto agli snapshot in stile ADExplorer.

## Stealth AD Collection Workflow

The following workflow shows how to enumerate **oggetti di dominio & ADCS** su ADWS, convertirli in BloodHound JSON e cercare percorsi di attacco basati su certificati – il tutto da Linux:

1. **Tunnel 9389/TCP** dalla rete target alla tua macchina (e.g. via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  Esporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` o usa SoaPy’s `--proxyHost/--proxyPort`.

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
5. **Carica lo ZIP** nella GUI di BloodHound ed esegui query cypher come `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` per rivelare percorsi di escalation dei certificati (ESC1, ESC8, ecc.).

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
| Enumerazione ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lettura/scrittura |
| Dump ADWS ad alto volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modalità BH/ADCS/DNS |
| Import per BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Converte i log di SoaPy/ldapsearch |
| Compromissione dei certificati | [Certipy](https://github.com/ly4k/Certipy) | Può essere instradato attraverso lo stesso SOCKS |
| Enumerazione ADWS e modifiche agli oggetti | [sopa](https://github.com/Macmod/sopa) | Client generico per interfacciarsi con endpoint ADWS noti - consente enumerazione, creazione di oggetti, modifiche di attributi e cambi di password |

## Riferimenti

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
