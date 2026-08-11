# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack** je tehnika koja napadačima omogućava da **zaobiđu Active Directory autentifikaciju** tako što **ubacuju glavnu lozinku** u LSASS proces svakog kontrolera domena. Nakon ubacivanja, glavna lozinka (podrazumevano **`mimikatz`**) može da se koristi za autentifikaciju kao **bilo koji korisnik domena**, dok njihove stvarne lozinke i dalje funkcionišu.<sup>[[1]](#references)[[2]](#references)</sup>

Ključne činjenice:

- Zahteva **Domain Admin/SYSTEM + SeDebugPrivilege** na svakom DC-u i mora da se **ponovo primeni nakon svakog restartovanja**.<sup>[[2]](#references)</sup>
- Klasična Mimikatz implementacija menja putanje za proveru **NTLM** i **Kerberos RC4 (etype 0x17)**; autentifikacija koja koristi samo AES **ne prihvata tu skeleton lozinku kroz RC4 hook**.<sup>[[2]](#references)</sup>
- Može doći u sukob sa paketima za LSA autentifikaciju nezavisnih proizvođača ili dodatnim provajderima za smart-card / MFA.<sup>[[2]](#references)</sup>
- Mimikatz modul prihvata opcioni switch `/letaes` kako bi izbegao menjanje Kerberos/AES hook-ova u slučaju problema sa kompatibilnošću.<sup>[[3]](#references)</sup>

### Execution

Klasični LSASS koji nije zaštićen pomoću PPL-a:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Ako **LSASS radi kao protected process light (PPL)**, debug pristup iz user-mode-a je blokiran. Istorijska Mimikatz procedura u nastavku učitava svoj kernel driver i uklanja zaštitu pre patchovanja LSASS-a. Credential Guard je zasebna kontrola izolacije i ne treba ga koristiti kao sinonim za PPL.<sup>[[3]](#references)[[4]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Nakon injection-a, autentifikujte se pomoću bilo kog domain naloga, ali koristite lozinku `mimikatz` (ili vrednost koju je postavio operator). Ne zaboravite da ponovite postupak na **svim DC-ovima** u okruženjima sa više DC-ova.

## Mere zaštite

- **Nadgledanje logova**
- System **Event ID 7045** (instalacija servisa/driver-a) za nepotpisane driver-e kao što je `mimidrv.sys`.
- **Sysmon**: Event ID 7 (učitavanje driver-a) za `mimidrv.sys`; Event ID 10 za sumnjiv pristup procesu `lsass.exe` iz procesa koji nisu system procesi.
- Security **Event ID 4673/4611** za korišćenje osetljivih privilegija ili anomalije pri registraciji LSA authentication package-a; korelirati sa neočekivanim 4624 logon-ima koji koriste RC4 (etype 0x17) sa DC-ova.
- **Ojačavanje LSASS-a**
- Održavajte **RunAsPPL** i **Credential Guard** omogućenim gde su podržani. Oni pružaju različite nivoe zaštite i zajedno povećavaju cenu i količinu telemetrije pokušaja izmene ili izvlačenja LSASS secrets.<sup>[[4]](#references)</sup>
- Onemogućite legacy **RC4** gde je moguće; Kerberos ticket-i ograničeni na AES sprečavaju RC4 hook putanju koju koristi skeleton key.<sup>[[2]](#references)</sup>
- Brzi PowerShell hunt-ovi:
- Detektujte instalacije nepotpisanih kernel driver-a: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Potražite Mimikatz driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Proverite da li je PPL enforced nakon reboot-a: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Za dodatne smernice o credential-hardening-u pogledajte [Windows zaštite credentials-a](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – Skeleton Key napad u Active Directory-ju (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton modul](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — Konfigurisanje dodatne LSA zaštite](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
