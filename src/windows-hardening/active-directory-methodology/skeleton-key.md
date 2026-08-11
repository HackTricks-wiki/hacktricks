# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

L'**attacco Skeleton Key** è una tecnica che consente agli attaccanti di **bypassare l'autenticazione di Active Directory** **iniettando una password master** nel processo LSASS di ogni domain controller. Dopo l'iniezione, la password master (predefinita: **`mimikatz`**) può essere utilizzata per autenticarsi come **qualsiasi utente del dominio**, mentre le relative password reali continuano a funzionare.<sup>[[1]](#references)[[2]](#references)</sup>

Informazioni chiave:

- Richiede **Domain Admin/SYSTEM + SeDebugPrivilege** su ogni DC e deve essere **riapplicata dopo ogni riavvio**.<sup>[[2]](#references)</sup>
- L'implementazione classica di Mimikatz applica patch ai percorsi di validazione **NTLM** e **Kerberos RC4 (etype 0x17)**; l'autenticazione con solo AES **non accetta quella password skeleton tramite l'hook RC4**.<sup>[[2]](#references)</sup>
- Può entrare in conflitto con pacchetti di autenticazione LSA di terze parti o con provider aggiuntivi per smart card / MFA.<sup>[[2]](#references)</sup>
- Il modulo Mimikatz accetta lo switch opzionale `/letaes` per evitare di modificare gli hook Kerberos/AES in caso di problemi di compatibilità.<sup>[[3]](#references)</sup>

### Execution

LSASS classico, non protetto da **PPL**:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Se **LSASS è in esecuzione come protected process light (PPL)**, l'accesso al debug in user-mode è bloccato. La procedura storica di Mimikatz riportata di seguito carica il suo kernel driver e rimuove la protezione prima di applicare il patching a LSASS. Credential Guard è un controllo di isolamento separato e non deve essere usato come sinonimo di PPL.<sup>[[3]](#references)[[4]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Dopo l'injection, autenticati con un account di dominio qualsiasi, ma usa la password `mimikatz` (o il valore impostato dall'operatore). Ricorda di ripetere l'operazione su **tutti i DC** negli ambienti con più DC.

## Mitigations

- **Monitoraggio dei log**
- **Event ID 7045** di sistema (installazione di servizi/driver) per driver non firmati come `mimidrv.sys`.
- **Sysmon**: Event ID 7 (caricamento del driver) per `mimidrv.sys`; Event ID 10 per accessi sospetti a `lsass.exe` da processi non di sistema.
- **Event ID 4673/4611** di sicurezza per l'uso di privilegi sensibili o anomalie nella registrazione dei pacchetti di autenticazione LSA; correla questi eventi con accessi 4624 imprevisti che utilizzano RC4 (etype 0x17) dai DC.
- **Hardening di LSASS**
- Mantieni **RunAsPPL** e **Credential Guard** abilitati dove supportati. Forniscono protezioni diverse e, insieme, aumentano il costo e la telemetria dei tentativi di modificare o estrarre i segreti di LSASS.<sup>[[4]](#references)</sup>
- Disabilita **RC4** quando possibile; i ticket Kerberos limitati ad AES impediscono il percorso di hook RC4 utilizzato da skeleton key.<sup>[[2]](#references)</sup>
- Ricerche rapide con PowerShell:
- Rileva le installazioni di driver kernel non firmati: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Cerca il driver di Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Verifica che PPL sia applicato dopo il riavvio: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Per ulteriori indicazioni sull'hardening delle credenziali, consulta [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – Attacco Skeleton Key in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Modulo misc::skeleton di Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — Configurare la protezione LSA aggiuntiva](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
