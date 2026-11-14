# Informacje w drukarkach

{{#include ../../banners/hacktricks-training.md}}

Drukarka z zapisanymi danymi logowania LDAP może je ujawnić, jeśli zmieni się ustawienie serwera, a następnie uwierzytelni się ona w nieautoryzowanym punkcie końcowym.<sup>[[2]](#references)</sup> Wynik zależy od metody bind: niezabezpieczony simple bind ujawnia hasło, natomiast bind typu SASL challenge-response nie ujawnia go w postaci tekstu jawnego.<sup>[[8]](#references)</sup> Zobacz [uwierzytelnianie LDAP i bezpieczeństwo transportu](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks).

Ponadto wiele drukarek zawiera **logi z nazwami użytkowników** lub może nawet **pobrać wszystkie nazwy użytkowników** z kontrolera domeny.

Wszystkie te **wrażliwe informacje** oraz powszechny **brak zabezpieczeń** sprawiają, że drukarki są bardzo interesujące dla atakujących.

Kilka wprowadzających wpisów na blogach na ten temat:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Konfiguracja drukarki

- **Lokalizacja**: Lista serwerów LDAP zwykle znajduje się w interfejsie internetowym (np. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Działanie**: Wiele wbudowanych serwerów internetowych pozwala zmieniać serwery LDAP **bez ponownego wprowadzania danych logowania** (funkcja zwiększająca wygodę → zagrożenie bezpieczeństwa).
- **Exploit**: Przekieruj adres serwera LDAP na host kontrolowany przez atakującego, a następnie użyj przycisku *Test Connection* / *Address Book Sync*, aby wymusić bind drukarki z Twoim hostem.

---

## Przechwytywanie danych logowania

### Metoda 1 – nasłuch Netcat

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Proste żądanie BindRequest może ujawnić DN i hasło użyte do bind w strumieniu BER, nawet jeśli serwer później odrzuci logowanie. Samo anonimowe wyszukiwanie lub negocjacja SASL nie ujawniają zapisanego hasła.<sup>[[8]](#references)</sup>

Zwykły nasłuchujący `nc` na porcie 636/3269 zobaczy uzgadnianie TLS, a nie bind LDAP. LDAPS wymaga punktu końcowego obsługującego TLS. Sama walidacja certyfikatu nie zapobiega pass-back, jeśli drukarka akceptuje zmienioną nazwę hosta, a nowy punkt końcowy ma prawidłowy certyfikat dla tej nazwy; klient musi również ograniczać, który serwer jest uprawniony do otrzymania zapisanych poświadczeń.<sup>[[8]](#references)</sup>

### Metoda 2 – Pełny nieautoryzowany serwer LDAP (zalecana)

Drukarka może wymagać prawidłowej odpowiedzi LDAP, zanim podejmie próbę bind.<sup>[[10]](#references)</sup> Pełny serwer LDAP może obsłużyć tę wstępną wymianę, ale nie sprawi, że klient przypięty do silnego mechanizmu SASL lub zamierzonego serwera TLS ujawni swoje hasło.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Traktuj wyszukanie jako dowód nawiązania połączenia, a nie dowód ujawnienia hasła. Hasło zostaje ujawnione tylko wtedy, gdy klient wysyła bind zawierający hasło w postaci jawnego tekstu; sprawdź rzeczywisty mechanizm bind i stan TLS.<sup>[[8]](#references)</sup>

> 💡  Responder zawiera nieautoryzowane usługi uwierzytelniania LDAP i SMB. Prosty bind LDAP może ujawnić skonfigurowane hasło, natomiast uwierzytelnianie NTLM dostarcza dane challenge-response; nie opisuj obu tych wyników jako hasła w postaci jawnego tekstu.

### Wybór mechanizmu SASL

Niektóre klienty LDAP w drukarkach wybierają spośród mechanizmów ogłaszanych przez serwer LDAP.<sup>[[8]](#references)[[10]](#references)</sup> Badania wykazały, że klient akceptujący ogłaszany mechanizm SASL przesyłający hasło jawnym tekstem może wysłać hasło, podczas gdy jego zwykła negocjacja NTLM dostarczyłaby tylko dane challenge-response.<sup>[[9]](#references)[[10]](#references)</sup> Jest to **błąd w polityce klienta**, a nie właściwość wszystkich bindów SASL: klient, który wymaga silniejszego mechanizmu lub przypina zaufany serwer TLS, powinien zamiast tego odrzucić połączenie.<sup>[[8]](#references)</sup> OpenLDAP domyślnie wyłącza mechanizmy SASL umożliwiające przesyłanie hasła jawnym tekstem, więc standardowy demon nie potwierdza, że takie zachowanie występuje w drukarce.<sup>[[11]](#references)</sup>

---

## Najnowsze podatności Pass-Back (2024–2025)

Pass-back *nie jest* problemem teoretycznym — w 2024 i 2025 roku producenci nadal publikują ostrzeżenia opisujące dokładnie tę klasę ataków.

### Xerox VersaLink – CVE-2024-12510 i CVE-2024-12511

Oprogramowanie układowe w wersji ≤ 57.69.91 urządzeń MFP Xerox VersaLink C70xx pozwalało uwierzytelnionemu administratorowi (lub dowolnej osobie, jeśli pozostawiono domyślne dane logowania) na:

* **CVE-2024-12510 – LDAP pass-back**: zmianę adresu serwera LDAP i wywołanie wyszukiwania, co powodowało, że urządzenie ujawniało skonfigurowane dane logowania Windows na hoście kontrolowanym przez atakującego.
* **CVE-2024-12511 – SMB/FTP pass-back**: identyczny problem występował przy użyciu miejsc docelowych *scan-to-folder*, ujawniając dane NetNTLMv2 lub dane logowania FTP w postaci jawnego tekstu.<sup>[[2]](#references)</sup>

Prosty listener, taki jak:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

lub nieautoryzowany serwer SMB (`impacket-smbserver`) wystarczy, aby przechwycić dane uwierzytelniające.  

### Canon imageRUNNER / imageCLASS – ostrzeżenie z 20 maja 2025 r.

Canon potwierdził podatność **SMTP/LDAP pass-back** w dziesiątkach linii produktów Laser i MFP. Atakujący z dostępem administratora może zmodyfikować konfigurację serwera i uzyskać zapisane dane uwierzytelniające LDAP **lub** SMTP (wiele organizacji używa konta z podwyższonymi uprawnieniami do funkcji skanowania i wysyłania poczty).<sup>[[3]](#references)</sup>

Wskazówki producenta wyraźnie zalecają:

1. Zaktualizowanie firmware’u do poprawionej wersji, gdy tylko będzie dostępna.
2. Używanie silnych, unikalnych haseł administratora.
3. Unikanie kont AD z podwyższonymi uprawnieniami przy integracji drukarek.

---

### Urządzenia Brother i warianty OEM – dostęp do danych uwierzytelniających usług na podstawie numeru seryjnego

Ujawniona w 2025 r. skoordynowana podatność pokazała szczególnie przydatny łańcuch ataku na podatnych urządzeniach Brother; część zestawu podatności dotyczy również modeli OEM, dlatego należy sprawdzić konkretny model w ostrzeżeniu jego producenta. Nieuwierzytelniony atakujący może uzyskać numer seryjny urządzenia przez HTTP/HTTPS/IPP na podatnym firmware, a numery seryjne mogą być też dostępne za pośrednictwem protokołów zarządzania, takich jak SNMP lub PJL. Jeśli hasło fabryczne nigdy nie zostało zmienione, numer seryjny pozwala deterministycznie ustalić hasło administratora. Po uwierzytelnieniu odrębna podatność pass-back CVE-2024-51984 ujawnia jawnym tekstem skonfigurowane hasła do usług zewnętrznych, takich jak LDAP lub FTP, zmieniając dostęp do zarządzania drukarką w źródło możliwych do ponownego użycia danych uwierzytelniających sieci. Firmware usuwa problem ujawniania haseł do usług, ale w przypadku wcześniej wyprodukowanych urządzeń operator nadal musi zastąpić początkowe hasło administratora wyprowadzone z numeru seryjnego.<sup>[[6]](#references)</sup>

Bieżąca wersja Metasploit zawiera moduł pomocniczy, który wykrywa numer seryjny przez HTTP, SNMP lub PJL, generuje potencjalne początkowe hasło i opcjonalnie sprawdza je w konsoli webowej. `DiscoverSerialVia=AUTO` próbuje obsługiwanych metod wykrywania; jeśli numer seryjny znajduje się już w ewidencji zasobów, zamiast tego podaj `TargetSerial`.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Używaj wyników wyłącznie do weryfikacji autoryzowanych zasobów. To, czy hasło zadziała, zależy od dokładnego modelu i, co najważniejsze, od tego, czy fabryczne hasło administratora zostało już zmienione.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Zautomatyzowane narzędzia do enumeracji / exploitation

| Narzędzie | Przeznaczenie | Przykład |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Nadużycia PostScript/PJL/PCL, dostęp do systemu plików, sprawdzanie domyślnych poświadczeń, *wykrywanie SNMP*; zobacz [ocenę PJL](../../network-services-pentesting/9100-pjl.md) | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Pozyskiwanie konfiguracji (w tym książek adresowych i poświadczeń LDAP) przez HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Uruchamianie fałszywych usług uwierzytelniania i przechwytywanie/przekazywanie NetNTLM z wywołań zwrotnych SMB | `sudo responder -I eth0 -v` |
| **Moduł pomocniczy Metasploit Brother** | Wykrywanie numeru seryjnego, wyznaczanie potencjalnego fabrycznego hasła administratora i weryfikowanie dostępu do konsoli WWW | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Zabezpieczenia i wykrywanie

1. **Niezwłocznie instaluj poprawki / aktualizuj firmware** urządzeń MFP (sprawdzaj biuletyny PSIRT producenta).
2. **Zmień fabryczne hasła administratora** – sam firmware nie usuwa początkowych haseł wyznaczanych na podstawie numeru seryjnego z wcześniej wyprodukowanych, podatnych urządzeń Brother/OEM.<sup>[[6]](#references)</sup>
3. **Konta usługowe z minimalnymi uprawnieniami** – nigdy nie używaj konta Domain Admin do LDAP/SMB/SMTP; ogranicz zakres OU do *tylko do odczytu*.
4. **Ogranicz dostęp do interfejsów zarządzania** – umieść interfejsy WWW/IPP/SNMP drukarki w sieci VLAN do zarządzania lub za ACL/VPN.
5. **Ogranicz ruch wychodzący drukarki** – zezwalaj każdemu urządzeniu na łączenie się wyłącznie z oczekiwanymi miejscami docelowymi DC/LDAP, poczty, DNS/NTP, drukowania i plików skanowania. Pass-back wymaga połączenia zwrotnego z punktem końcowym wybranym przez atakującego.
6. **Wyłącz nieużywane protokoły** – FTP, Telnet, raw-9100, starsze szyfry SSL.
7. **Włącz rejestrowanie audytowe** – niektóre urządzenia mogą wysyłać do syslog informacje o nieudanych próbach LDAP/SMTP; koreluj nieoczekiwane powiązania.
8. **Monitoruj miejsca docelowe uwierzytelniania** – generuj alerty, gdy drukarka inicjuje połączenie LDAP, SMB, SMTP lub FTP z hostem spoza swojej listy dozwolonych, zwłaszcza bezpośrednio po zalogowaniu do interfejsu zarządzania lub zmianie konfiguracji.
9. **SNMPv3 lub wyłącz SNMP** – community `public` często powoduje leak informacji o urządzeniu i numerze seryjnym.

---



---



## References

- [1] [To tylko drukarka… Co najgorszego może się stać?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Drukarka wielofunkcyjna Xerox Versalink C7025: podatności na atak Pass-Back (naprawione)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004: ograniczanie skutków podatności i działania naprawcze dotyczące drukarek produkcyjnych, wielofunkcyjnych drukarek biurowych i do małych biur oraz drukarek laserowych](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Pozyskiwanie poświadczeń domenowych przez drukarkę za pomocą Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting drukarek wielofunkcyjnych podczas testów penetracyjnych](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Wiele urządzeń Brother: wiele podatności (naprawione)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: moduł obejścia uwierzytelniania domyślnym hasłem administratora Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – metody uwierzytelniania LDAP i mechanizmy bezpieczeństwa](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [Serwer Docker LDAP passback](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [Atak LDAP pass back – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – właściwości bezpieczeństwa SASL](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
