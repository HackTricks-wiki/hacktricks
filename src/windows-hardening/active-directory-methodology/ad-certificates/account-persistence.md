# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**To mały podsumowanie rozdziałów dotyczących utrzymywania dostępu w maszynach z niesamowitych badań z [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## **Zrozumienie kradzieży poświadczeń aktywnego użytkownika za pomocą certyfikatów – PERSIST1**

W scenariuszu, w którym certyfikat umożliwiający uwierzytelnianie w domenie może być żądany przez użytkownika, atakujący ma możliwość **żądania** i **kradzieży** tego certyfikatu, aby **utrzymać dostęp** w sieci. Domyślnie szablon `User` w Active Directory pozwala na takie żądania, chociaż czasami może być wyłączony.

Używając narzędzia o nazwie [**Certify**](https://github.com/GhostPack/Certify), można wyszukiwać ważne certyfikaty, które umożliwiają trwały dostęp:
```bash
Certify.exe find /clientauth
```
Podkreślono, że moc certyfikatu polega na jego zdolności do **uwierzytelniania jako użytkownik**, do którego należy, niezależnie od jakichkolwiek zmian haseł, pod warunkiem, że certyfikat pozostaje **ważny**.

Certyfikaty można zamawiać za pomocą interfejsu graficznego przy użyciu `certmgr.msc` lub za pomocą wiersza poleceń z `certreq.exe`. Dzięki **Certify** proces zamawiania certyfikatu jest uproszczony w następujący sposób:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Po pomyślnym żądaniu generowany jest certyfikat wraz z jego kluczem prywatnym w formacie `.pem`. Aby przekonwertować to na plik `.pfx`, który jest użyteczny w systemach Windows, używa się następującego polecenia:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Plik `.pfx` może być następnie przesłany do systemu docelowego i użyty z narzędziem o nazwie [**Rubeus**](https://github.com/GhostPack/Rubeus) do żądania Ticket Granting Ticket (TGT) dla użytkownika, przedłużając dostęp atakującego na czas, gdy certyfikat jest **ważny** (zazwyczaj przez rok):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Ważne ostrzeżenie dotyczy tego, jak ta technika, w połączeniu z inną metodą opisaną w sekcji **THEFT5**, pozwala atakującemu na trwałe uzyskanie **NTLM hash** konta bez interakcji z Local Security Authority Subsystem Service (LSASS) i z kontekstu o niskich uprawnieniach, co zapewnia bardziej dyskretną metodę kradzieży poświadczeń na dłuższy czas.

## **Uzyskiwanie trwałości maszyny za pomocą certyfikatów - PERSIST2**

Inna metoda polega na zarejestrowaniu konta maszyny skompromitowanego systemu dla certyfikatu, wykorzystując domyślny szablon `Machine`, który pozwala na takie działania. Jeśli atakujący uzyska podwyższone uprawnienia w systemie, może użyć konta **SYSTEM** do żądania certyfikatów, co zapewnia formę **trwałości**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Ten dostęp umożliwia atakującemu uwierzytelnienie się do **Kerberos** jako konto maszyny i wykorzystanie **S4U2Self** do uzyskania biletów serwisowych Kerberos dla dowolnej usługi na hoście, co skutecznie przyznaje atakującemu trwały dostęp do maszyny.

## **Rozszerzanie trwałości poprzez odnawianie certyfikatów - PERSIST3**

Ostatnia omawiana metoda polega na wykorzystaniu **ważności** i **okresów odnawiania** szablonów certyfikatów. Poprzez **odnawianie** certyfikatu przed jego wygaśnięciem, atakujący może utrzymać uwierzytelnienie do Active Directory bez potrzeby dodatkowych rejestracji biletów, co mogłoby pozostawić ślady na serwerze Urzędu Certyfikacji (CA).

### Odnawianie certyfikatu z Certify 2.0

Zaczynając od **Certify 2.0**, proces odnawiania jest w pełni zautomatyzowany dzięki nowemu poleceniu `request-renew`. Mając wcześniej wydany certyfikat (w formacie **base-64 PKCS#12**), atakujący może go odnowić bez interakcji z pierwotnym właścicielem – idealne do dyskretnej, długoterminowej trwałości:
```powershell
Certify.exe request-renew --ca SERVER\\CA-NAME \
--cert-pfx MIACAQMwgAYJKoZIhvcNAQcBoIAkgA...   # original PFX
```
Polecenie zwróci nowy PFX, który jest ważny przez kolejny pełny okres życia, co pozwala na kontynuowanie uwierzytelniania nawet po wygaśnięciu lub unieważnieniu pierwszego certyfikatu.

## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)

{{#include ../../../banners/hacktricks-training.md}}
