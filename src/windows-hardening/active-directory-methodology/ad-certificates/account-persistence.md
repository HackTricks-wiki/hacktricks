# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**To jest małe podsumowanie rozdziałów dotyczących utrzymywania maszyn w niesamowitym badaniu z [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## **Zrozumienie kradzieży poświadczeń aktywnego użytkownika za pomocą certyfikatów – PERSIST1**

W scenariuszu, w którym certyfikat umożliwiający uwierzytelnianie w domenie może być żądany przez użytkownika, atakujący ma możliwość **zażądania** i **ukradzenia** tego certyfikatu, aby **utrzymać trwałość** w sieci. Domyślnie szablon `User` w Active Directory pozwala na takie żądania, chociaż czasami może być wyłączony.

Używając narzędzia o nazwie [**Certify**](https://github.com/GhostPack/Certify), można wyszukiwać ważne certyfikaty, które umożliwiają trwały dostęp:
```bash
Certify.exe find /clientauth
```
Podkreśla się, że moc certyfikatu polega na jego zdolności do **uwierzytelniania jako użytkownik**, do którego należy, niezależnie od jakichkolwiek zmian haseł, pod warunkiem, że certyfikat pozostaje **ważny**.

Certyfikaty można zamawiać za pomocą interfejsu graficznego przy użyciu `certmgr.msc` lub za pomocą wiersza poleceń z `certreq.exe`. Dzięki **Certify** proces zamawiania certyfikatu jest uproszczony w następujący sposób:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Po pomyślnym żądaniu generowany jest certyfikat wraz z jego kluczem prywatnym w formacie `.pem`. Aby przekonwertować to na plik `.pfx`, który jest użyteczny w systemach Windows, używa się następującego polecenia:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Plik `.pfx` może być następnie przesłany do systemu docelowego i użyty z narzędziem o nazwie [**Rubeus**](https://github.com/GhostPack/Rubeus) do żądania Ticket Granting Ticket (TGT) dla użytkownika, przedłużając dostęp atakującego tak długo, jak certyfikat jest **ważny** (zazwyczaj przez rok):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Ważne ostrzeżenie dotyczy tego, jak ta technika, w połączeniu z inną metodą opisaną w sekcji **THEFT5**, pozwala atakującemu na trwałe uzyskanie **NTLM hash** konta bez interakcji z Local Security Authority Subsystem Service (LSASS) i z kontekstu niepodwyższonego, co zapewnia bardziej dyskretną metodę kradzieży poświadczeń na dłuższy czas.

## **Zyskiwanie trwałości maszyny za pomocą certyfikatów - PERSIST2**

Inna metoda polega na zarejestrowaniu konta maszyny skompromitowanego systemu na certyfikat, wykorzystując domyślny szablon `Machine`, który pozwala na takie działania. Jeśli atakujący uzyska podwyższone uprawnienia w systemie, może użyć konta **SYSTEM** do żądania certyfikatów, co zapewnia formę **trwałości**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Ten dostęp umożliwia atakującemu uwierzytelnienie się do **Kerberos** jako konto maszyny i wykorzystanie **S4U2Self** do uzyskania biletów serwisowych Kerberos dla dowolnej usługi na hoście, co skutecznie przyznaje atakującemu trwały dostęp do maszyny.

## **Rozszerzanie trwałości poprzez odnawianie certyfikatów - PERSIST3**

Ostatnia omawiana metoda polega na wykorzystaniu **ważności** i **okresów odnawiania** szablonów certyfikatów. Poprzez **odnawianie** certyfikatu przed jego wygaśnięciem, atakujący może utrzymać uwierzytelnienie do Active Directory bez potrzeby dodatkowych rejestracji biletów, co mogłoby pozostawić ślady na serwerze Urzędu Certyfikacji (CA).

Podejście to pozwala na metodę **rozszerzonej trwałości**, minimalizując ryzyko wykrycia poprzez mniejszą liczbę interakcji z serwerem CA i unikanie generowania artefaktów, które mogłyby zaalarmować administratorów o intruzji.

{{#include ../../../banners/hacktricks-training.md}}
