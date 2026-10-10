# Informacje zapisane w drukarkach

{{#include ../../banners/hacktricks-training.md}}

W Internecie można znaleźć kilka blogów, które **podkreślają zagrożenia związane z pozostawianiem drukarek skonfigurowanych do korzystania z LDAP z domyślnymi lub słabymi** danymi logowania.  \
Dzieje się tak, ponieważ atakujący może **nakłonić drukarkę do uwierzytelnienia się na fałszywym serwerze LDAP** (zwykle wystarczy `nc -vv -l -p 389` lub `slapd -d 2`) i przechwycić **dane logowania drukarki w postaci jawnego tekstu**.

Ponadto w wielu drukarkach znajdują się **logi zawierające nazwy użytkowników** lub można za ich pomocą **pobrać wszystkie nazwy użytkowników z kontrolera domeny**.

Wszystkie te **poufne informacje** oraz powszechny **brak zabezpieczeń** sprawiają, że drukarki są bardzo interesujące dla atakujących.

Kilka blogów wprowadzających w ten temat:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Konfiguracja drukarki

- **Lokalizacja**: Lista serwerów LDAP zwykle znajduje się w interfejsie internetowym (np. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Działanie**: Wiele wbudowanych serwerów internetowych pozwala zmieniać ustawienia serwera LDAP **bez ponownego wpisywania danych logowania** (udogodnienie → zagrożenie bezpieczeństwa).
- **Wykorzystanie**: Zmień adres serwera LDAP na adres hosta kontrolowanego przez atakującego i użyj przycisku *Test Connection* / *Address Book Sync*, aby wymusić na drukarce połączenie z tym serwerem.

---

## Przechwytywanie danych logowania

### Metoda 1 – Nasłuch Netcat

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Małe/stare urządzenia MFP mogą wysyłać prosty *simple-bind*, w którym DN i hasło bind są widoczne w surowym strumieniu BER. Nowoczesne urządzenia zwykle najpierw wykonują zapytanie anonimowe, a następnie próbują wykonać bind, więc wyniki są różne.<sup>[[1]](#references)</sup>

Zwykły nasłuch `nc` na portach 636/3269 odbiera wyłącznie szyfrogram TLS; testowanie LDAPS wymaga endpointu LDAP obsługującego TLS, a przekierowanie powinno się nie powieść, gdy urządzenie prawidłowo weryfikuje certyfikat serwera.

### Method 2 – Full Rogue LDAP server (recommended)

Ponieważ wiele urządzeń wykonuje anonimowe wyszukiwanie *przed* uwierzytelnieniem, uruchomienie prawdziwego demona LDAP zapewnia znacznie bardziej wiarygodne wyniki:<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Gdy drukarka wykonuje zapytanie, w danych debugowania zobaczysz poświadczenia w postaci jawnego tekstu.

> 💡 Responder obejmuje fałszywe usługi uwierzytelniania LDAP i SMB. Proste LDAP bind może ujawnić skonfigurowane hasło, natomiast uwierzytelnianie NTLM generuje dane challenge-response; nie należy opisywać obu wyników jako hasła w postaci jawnego tekstu.

---

## Najnowsze podatności Pass-Back (2024-2025)

Pass-back *nie jest* problemem teoretycznym – w 2024/2025 dostawcy wciąż publikują ostrzeżenia, które dokładnie opisują tę klasę ataków.

### Xerox VersaLink – CVE-2024-12510 i CVE-2024-12511

Firmware ≤ 57.69.91 urządzeń Xerox VersaLink C70xx MFP umożliwiało uwierzytelnionemu administratorowi (lub każdemu, jeśli nie zmieniono domyślnych danych logowania):

* **CVE-2024-12510 – LDAP pass-back**: zmianę adresu serwera LDAP i wywołanie zapytania, co powoduje wyciek skonfigurowanych poświadczeń Windows z urządzenia na hosta kontrolowanego przez atakującego.
* **CVE-2024-12511 – SMB/FTP pass-back**: identyczny problem za pośrednictwem miejsc docelowych *scan-to-folder*, powodujący wyciek danych NetNTLMv2 lub poświadczeń FTP w postaci jawnego tekstu.<sup>[[2]](#references)</sup>

Prosty nasłuchujący, taki jak:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

lub nieautoryzowany serwer SMB (`impacket-smbserver`) wystarczy do przechwycenia poświadczeń.

### Canon imageRUNNER / imageCLASS – zalecenie z 20 maja 2025 r.

Canon potwierdził lukę typu **SMTP/LDAP pass-back** w dziesiątkach linii produktów Laser i MFP. Atakujący z dostępem administratora może zmienić konfigurację serwera i odzyskać zapisane poświadczenia LDAP **lub** SMTP (wiele organizacji używa uprzywilejowanego konta do obsługi skanowania do poczty).<sup>[[3]](#references)</sup>

Wytyczne producenta wyraźnie zalecają:

1. Jak najszybszą aktualizację do poprawionego firmware.
2. Używanie silnych, unikatowych haseł administratora.
3. Unikanie uprzywilejowanych kont AD do integracji z drukarkami.

---

### Urządzenia Brother i warianty OEM – dostęp administratora wyznaczany na podstawie numeru seryjnego umożliwia uzyskanie poświadczeń do usług

Skoordynowane ujawnienie z 2025 r. pokazało szczególnie przydatny łańcuch ataku na podatnych urządzeniach Brother; część zestawu luk dotyczy również modeli OEM, dlatego należy sprawdzić dokładny model w zaleceniach producenta. Atakujący nieuwierzytelniony może odczytać numer seryjny urządzenia przez HTTP/HTTPS/IPP na podatnym firmware, a numery seryjne mogą być również dostępne za pośrednictwem protokołów zarządzania, takich jak SNMP lub PJL. Jeśli fabryczne hasło nigdy nie zostało zmienione, numer seryjny pozwala deterministycznie wyznaczyć hasło administratora. Po uwierzytelnieniu odrębna luka typu pass-back CVE-2024-51984 ujawnia jawnym tekstem skonfigurowane hasła do usług zewnętrznych, takich jak LDAP lub FTP, zamieniając dostęp do zarządzania drukarką w poświadczenia sieciowe wielokrotnego użytku. Firmware usuwa lukę ujawniającą hasła do usług, ale w urządzeniach wyprodukowanych wcześniej operator nadal musi zmienić początkowe hasło administratora wyznaczane na podstawie numeru seryjnego.<sup>[[6]](#references)</sup>

Aktualna wersja Metasploit zawiera moduł pomocniczy, który wykrywa numer seryjny przez HTTP, SNMP lub PJL, generuje kandydackie początkowe hasło i opcjonalnie sprawdza je w konsoli internetowej. `DiscoverSerialVia=AUTO` wypróbowuje obsługiwane metody wykrywania; jeśli numer seryjny znajduje się już w wykazie zasobów, zamiast tego podaj `TargetSerial`.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Wyniku używaj wyłącznie do weryfikacji autoryzowanych zasobów. To, czy hasło zadziała, zależy od konkretnego modelu, a przede wszystkim od tego, czy fabryczne hasło administratora zostało już zmienione.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Zautomatyzowane narzędzia do enumeracji / exploitation

| Narzędzie | Cel | Przykład |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Nadużywanie PostScript/PJL/PCL, dostęp do systemu plików, sprawdzanie domyślnych poświadczeń, *wykrywanie SNMP* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Pobieranie konfiguracji (w tym książek adresowych i poświadczeń LDAP) przez HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Uruchamianie fałszywych usług uwierzytelniania oraz przechwytywanie/przekazywanie NetNTLM z wywołań zwrotnych SMB | `sudo responder -I eth0 -v` |
| **Moduł pomocniczy Metasploit Brother** | Wykrywanie numeru seryjnego, wyliczanie potencjalnego fabrycznego hasła administratora i weryfikacja dostępu do konsoli WWW | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Zabezpieczanie i wykrywanie

1. **Niezwłocznie instaluj poprawki / aktualizuj firmware** urządzeń MFP (sprawdzaj biuletyny PSIRT dostawcy).
2. **Zmień fabryczne hasła administratora** – sam firmware nie usuwa początkowych haseł wyliczanych na podstawie numeru seryjnego z wcześniej wyprodukowanych urządzeń Brother/OEM, których dotyczy problem.<sup>[[6]](#references)</sup>
3. **Konta usługowe z minimalnymi uprawnieniami** – nigdy nie używaj konta Domain Admin do LDAP/SMB/SMTP; ogranicz zakres OU do *tylko do odczytu*.
4. **Ogranicz dostęp administracyjny** – umieść interfejsy WWW/IPP/SNMP drukarek w sieci VLAN do zarządzania lub za ACL/VPN.
5. **Ogranicz ruch wychodzący drukarek** – zezwalaj każdemu urządzeniu na łączenie się wyłącznie z oczekiwanymi punktami docelowymi DC/LDAP, poczty, DNS/NTP, druku i plików skanowania. Pass-back wymaga połączenia zwrotnego z punktem końcowym wybranym przez atakującego.
6. **Wyłącz nieużywane protokoły** – FTP, Telnet, raw-9100, starsze szyfry SSL.
7. **Włącz rejestrowanie audytowe** – niektóre urządzenia mogą wysyłać błędy LDAP/SMTP do syslog; koreluj nieoczekiwane próby bind.
8. **Monitoruj docelowe hosty uwierzytelniania** – generuj alerty, gdy drukarka inicjuje połączenie LDAP, SMB, SMTP lub FTP z hostem spoza listy dozwolonych, szczególnie tuż po zalogowaniu do interfejsu zarządzania lub zmianie konfiguracji.
9. **SNMPv3 lub wyłącz SNMP** – community `public` często ujawnia informacje o urządzeniu i numerze seryjnym.

---



---

## References

- [1] [To tylko drukarka… Co najgorszego może się stać?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Urządzenie wielofunkcyjne Xerox Versalink C7025: podatności na atak Pass-Back (naprawione)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004: ograniczanie skutków / naprawa podatności w drukarkach produkcyjnych, urządzeniach wielofunkcyjnych do biur i małych biur oraz drukarkach laserowych](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Pozyskiwanie poświadczeń domenowych przez drukarkę za pomocą Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting urządzeń wielofunkcyjnych podczas testów penetracyjnych](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Wiele urządzeń Brother: wiele podatności (NAPRAWIONE)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: moduł obejścia uwierzytelniania domyślnego administratora Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
