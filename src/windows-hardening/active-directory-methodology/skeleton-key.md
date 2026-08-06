# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key napad

**Skeleton Key napad** je tehnika koja napadačima omogućava da **zaobiđu Active Directory autentifikaciju** tako što **ubacuju glavnu lozinku** u LSASS proces svakog kontrolera domena. Nakon ubacivanja, glavna lozinka (podrazumevano **`mimikatz`**) može da se koristi za autentifikaciju kao **bilo koji korisnik domena**, dok njihove stvarne lozinke i dalje funkcionišu.<sup>[[1]](#references)[[2]](#references)</sup>

Ključne činjenice:

- Zahteva **Domain Admin/SYSTEM + SeDebugPrivilege** na svakom DC-u i mora biti **ponovo primenjen nakon svakog restartovanja**.<sup>[[2]](#references)</sup>
- Menja putanje za validaciju **NTLM** i **Kerberos RC4 (etype 0x17)**; realm-ovi koji koriste samo AES ili nalozi koji zahtevaju AES **neće prihvatiti skeleton key**.<sup>[[2]](#references)</sup>
- Može doći u konflikt sa authentication packages trećih strana ili dodatnim smart-card / MFA provajderima.<sup>[[2]](#references)</sup>
- Mimikatz modul prihvata opcioni switch `/letaes` kako bi izbegao menjanje Kerberos/AES hooks u slučaju problema sa kompatibilnošću.<sup>[[3]](#references)</sup>

### Izvršavanje

Klasični LSASS koji nije zaštićen pomoću PPL-a:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Ako **LSASS radi kao PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), potreban je kernel driver za uklanjanje zaštite pre patchovanja LSASS-a:<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Nakon injection-a, autentifikujte se bilo kojim domain nalogom, ali koristite lozinku `mimikatz` (ili vrednost koju je postavio operator). Ne zaboravite da ponovite postupak na **svim DC-ovima** u okruženjima sa više DC-ova.

## Mere zaštite

- **Nadgledanje logova**
- System **Event ID 7045** (instalacija servisa/driver-a) za nepotpisane driver-e kao što je `mimidrv.sys`.
- **Sysmon**: Event ID 7 (učitavanje driver-a) za `mimidrv.sys`; Event ID 10 za sumnjiv pristup procesu `lsass.exe` iz nesistemskih procesa.
- Security **Event ID 4673/4611** za korišćenje osetljivih privilegija ili anomalije pri registraciji LSA authentication package-a; povezati ih sa neočekivanim 4624 logon-ima koji koriste RC4 (etype 0x17) sa DC-ova.
- **Ojačavanje LSASS-a**
- Održavajte **RunAsPPL/Credential Guard/Secure LSASS** omogućenim na DC-ovima kako biste napadače primorali na deployment kernel-mode driver-a (više telemetrije, teža eksploatacija).
- Onemogućite legacy **RC4** gde je moguće; Kerberos ticket-i ograničeni na AES sprečavaju RC4 hook putanju koju koristi skeleton key.<sup>[[2]](#references)</sup>
- Brzi PowerShell hunt-ovi:
- Detektujte instalacije nepotpisanih kernel driver-a: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Potražite Mimikatz driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Proverite da li je PPL nametnut nakon reboot-a: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Za dodatne smernice o hardening-u credential-a pogledajte [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [1] [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
