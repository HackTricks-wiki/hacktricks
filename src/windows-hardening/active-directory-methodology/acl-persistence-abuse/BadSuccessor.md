# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

## Overview

I Delegated Managed Service Accounts (**dMSAs**) sono un nuovo tipo di principale AD introdotto con **Windows Server 2025**. Sono progettati per sostituire gli account di servizio legacy consentendo una “migrazione” con un clic che copia automaticamente i Service Principal Names (SPNs), le appartenenze ai gruppi, le impostazioni di delega e persino le chiavi crittografiche dell'account precedente nel nuovo dMSA, offrendo alle applicazioni un passaggio senza soluzione di continuità ed eliminando il rischio di Kerberoasting.

I ricercatori di Akamai hanno scoperto che un singolo attributo — **`msDS‑ManagedAccountPrecededByLink`** — indica al KDC quale account legacy un dMSA “sostituisce”. Se un attaccante può scrivere quell'attributo (e attivare **`msDS‑DelegatedMSAState` → 2**), il KDC costruirà felicemente un PAC che **eredita ogni SID della vittima scelta**, consentendo effettivamente al dMSA di impersonare qualsiasi utente, inclusi gli Amministratori di Dominio.

## What exactly is a dMSA?

* Basato sulla tecnologia **gMSA** ma memorizzato come la nuova classe AD **`msDS‑DelegatedManagedServiceAccount`**.
* Supporta una **migrazione su richiesta**: chiamando `Start‑ADServiceAccountMigration` si collega il dMSA all'account legacy, si concede all'account legacy l'accesso in scrittura a `msDS‑GroupMSAMembership` e si attiva `msDS‑DelegatedMSAState` = 1.
* Dopo `Complete‑ADServiceAccountMigration`, l'account superato viene disabilitato e il dMSA diventa completamente funzionale; qualsiasi host che precedentemente utilizzava l'account legacy è automaticamente autorizzato a prelevare la password del dMSA.
* Durante l'autenticazione, il KDC incorpora un suggerimento **KERB‑SUPERSEDED‑BY‑USER** in modo che i client Windows 11/24H2 riprovino in modo trasparente con il dMSA.

## Requirements to attack
1. **Almeno un Windows Server 2025 DC** affinché la classe LDAP del dMSA e la logica KDC esistano.
2. **Qualsiasi diritto di creazione di oggetti o scrittura di attributi su un OU** (qualsiasi OU) – ad esempio, `Create msDS‑DelegatedManagedServiceAccount` o semplicemente **Create All Child Objects**. Akamai ha scoperto che il 91 % dei tenant nel mondo reale concede tali permessi “benigni” sugli OU a non amministratori.
3. Capacità di eseguire strumenti (PowerShell/Rubeus) da qualsiasi host unito al dominio per richiedere ticket Kerberos.
*Non è richiesto alcun controllo sull'utente vittima; l'attacco non tocca mai direttamente l'account target.*

## Step‑by‑step: BadSuccessor*privilege escalation

1. **Trova o crea un dMSA che controlli**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

Poiché hai creato l'oggetto all'interno di un OU a cui puoi scrivere, possiedi automaticamente tutti i suoi attributi.

2. **Simula una “migrazione completata” in due scritture LDAP**:
- Imposta `msDS‑ManagedAccountPrecededByLink = DN` di qualsiasi vittima (ad esempio `CN=Administrator,CN=Users,DC=lab,DC=local`).
- Imposta `msDS‑DelegatedMSAState = 2` (migrazione completata).

Strumenti come **Set‑ADComputer, ldapmodify**, o anche **ADSI Edit** funzionano; non sono necessari diritti di amministratore di dominio.

3. **Richiedi un TGT per il dMSA** — Rubeus supporta il flag `/dmsa`:

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

Il PAC restituito ora contiene il SID 500 (Amministratore) più i gruppi Amministratori di Dominio/Amministratori di Impresa.

## Gather all the users passwords

Durante le migrazioni legittime, il KDC deve consentire al nuovo dMSA di decrittografare **i ticket emessi all'account precedente prima del passaggio**. Per evitare di interrompere le sessioni attive, inserisce sia le chiavi correnti che le chiavi precedenti all'interno di un nuovo blob ASN.1 chiamato **`KERB‑DMSA‑KEY‑PACKAGE`**.

Poiché la nostra falsa migrazione afferma che il dMSA sostituisce la vittima, il KDC copia diligentemente la chiave RC4‑HMAC della vittima nella lista delle **chiavi precedenti** – anche se il dMSA non ha mai avuto una password “precedente”. Quella chiave RC4 non è salata, quindi è effettivamente l'hash NT della vittima, dando all'attaccante la capacità di **cracking offline o “pass‑the‑hash”**.

Pertanto, il collegamento di massa di migliaia di utenti consente a un attaccante di estrarre hash “su larga scala”, trasformando **BadSuccessor in un primitivo sia di escalation dei privilegi che di compromissione delle credenziali**.

## Tools

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## References

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)


{{#include ../../../banners/hacktricks-training.md}}
