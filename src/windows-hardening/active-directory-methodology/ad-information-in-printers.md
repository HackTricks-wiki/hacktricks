# Informacje w drukarkach

{{#include ../../banners/hacktricks-training.md}}

W Internecie znajduje się kilka blogów, które **podkreślają zagrożenia związane z pozostawianiem drukarek skonfigurowanych z LDAP i domyślnymi/słabymi** danymi uwierzytelniającymi do logowania.  \
Dzieje się tak, ponieważ attacker może **nakłonić drukarkę do uwierzytelnienia się względem rogue LDAP server** (zwykle wystarczy `nc -vv -l -p 389` lub `slapd -d 2`) i przechwycić **dane uwierzytelniające drukarki w jawnym tekście**.

Ponadto niektóre drukarki będą zawierać **logi z nazwami użytkowników** lub mogą nawet umożliwiać **pobranie wszystkich nazw użytkowników** z Domain Controller.

Wszystkie te **wrażliwe informacje** oraz powszechny **brak bezpieczeństwa** sprawiają, że drukarki są bardzo interesujące dla attackerów.

Kilka wprowadzających blogów na ten temat:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Konfiguracja drukarki

- **Lokalizacja**: Lista serwerów LDAP zwykle znajduje się w interfejsie webowym (np. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Działanie**: Wiele wbudowanych serwerów webowych umożliwia modyfikowanie serwerów LDAP **bez ponownego wprowadzania danych uwierzytelniających** (funkcja użyteczności → ryzyko bezpieczeństwa).
- **Exploit**: Przekieruj adres serwera LDAP na hosta kontrolowanego przez attackera i użyj przycisku *Test Connection* / *Address Book Sync*, aby wymusić wykonanie przez drukarkę bind do Ciebie.

---

## Przechwytywanie danych uwierzytelniających

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```
Małe/stare urządzenia MFP mogą wysyłać prosty *simple-bind*, w którym bind DN i hasło są widoczne w surowym strumieniu BER. Nowoczesne urządzenia zwykle najpierw wykonują anonimowe zapytanie, a następnie próbują wykonać bind, dlatego wyniki bywają różne.<sup>[[1]](#references)</sup>

Zwykły listener `nc` na portach 636/3269 odbiera wyłącznie ciphertext TLS; testowanie LDAPS wymaga endpointu LDAP obsługującego TLS, a przekierowanie powinno zakończyć się niepowodzeniem, gdy urządzenie prawidłowo weryfikuje certyfikat serwera.

### Metoda 2 – Full Rogue LDAP server (zalecane)

Ponieważ wiele urządzeń wykona anonimowe wyszukiwanie *przed* uwierzytelnieniem, uruchomienie rzeczywistego demona LDAP zapewnia znacznie bardziej wiarygodne wyniki:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Gdy drukarka wykona wyszukiwanie, zobaczysz dane uwierzytelniające w jawnym tekście w danych wyjściowych debugowania.

> 💡  Responder zawiera rogue LDAP i SMB authentication services. Proste LDAP bind może ujawnić skonfigurowane hasło, podczas gdy uwierzytelnianie NTLM generuje dane challenge-response; nie opisuj obu rezultatów jako hasła w jawnym tekście.

---

## Najnowsze luki Pass-Back (2024-2025)

Pass-back *nie jest* teoretycznym problemem – vendorzy nadal publikują w 2024/2025 advisories dokładnie opisujące tę klasę ataków.

### Xerox VersaLink – CVE-2024-12510 i CVE-2024-12511

Firmware ≤ 57.69.91 urządzeń MFP Xerox VersaLink C70xx pozwalał uwierzytelnionemu administratorowi (lub dowolnej osobie, jeśli pozostały domyślne dane uwierzytelniające) na:

* **CVE-2024-12510 – LDAP pass-back**: zmianę adresu serwera LDAP i wywołanie wyszukiwania, powodując leak skonfigurowanych danych uwierzytelniających Windows na host kontrolowany przez atakującego.
* **CVE-2024-12511 – SMB/FTP pass-back**: identyczny problem za pośrednictwem miejsc docelowych *scan-to-folder*, powodujący leak danych NetNTLMv2 lub danych uwierzytelniających FTP w jawnym tekście.<sup>[[2]](#references)</sup>

Wystarczy prosty listener, taki jak:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
lub fałszywy serwer SMB (`impacket-smbserver`) wystarczy do przechwycenia poświadczeń.

### Canon imageRUNNER / imageCLASS – komunikat z 20 maja 2025 r.

Firma Canon potwierdziła lukę typu **SMTP/LDAP pass-back** w dziesiątkach linii produktów Laser i MFP. Atakujący z dostępem administratora może zmodyfikować konfigurację serwera i pobrać zapisane poświadczenia LDAP **lub** SMTP (wiele organizacji używa uprzywilejowanego konta, aby umożliwić skanowanie do poczty e-mail).<sup>[[3]](#references)</sup>

Wytyczne producenta wyraźnie zalecają:

1. Jak najszybszą aktualizację do dostępnego firmware'u zawierającego poprawki.
2. Używanie silnych, unikalnych haseł administratora.
3. Unikanie uprzywilejowanych kont AD do integracji drukarek.

---

### Urządzenia Brother i warianty OEM – dostęp administratora wyprowadzany z numeru seryjnego do poświadczeń usług

Skoordynowane ujawnienie z 2025 roku wykazało szczególnie użyteczny łańcuch ataku na podatnych urządzeniach Brother; część zestawu podatności dotyczy również modeli OEM, dlatego należy zweryfikować dokładny model względem komunikatu producenta. Nieuwierzytelniony atakujący może uzyskać numer seryjny urządzenia przez HTTP/HTTPS/IPP na podatnym firmware, a numery seryjne mogą być również dostępne za pośrednictwem protokołów zarządzania, takich jak SNMP lub PJL. Jeśli hasło fabryczne nigdy nie zostało zmienione, numer seryjny deterministycznie pozwala wyprowadzić hasło administratora. Po uwierzytelnieniu odrębna luka pass-back CVE-2024-51984 ujawnia skonfigurowane hasła zewnętrznych usług, takich jak LDAP lub FTP, w postaci jawnego tekstu, zamieniając dostęp do zarządzania drukarką w możliwe do ponownego użycia poświadczenia sieciowe. Firmware usuwa ujawnianie haseł usług, ale wcześniej wyprodukowane urządzenia nadal wymagają od operatora zastąpienia początkowego hasła administratora wyprowadzanego z numeru seryjnego.<sup>[[6]](#references)</sup>

Obecna wersja Metasploit zawiera moduł pomocniczy, który wykrywa numer seryjny przez HTTP, SNMP lub PJL, generuje potencjalne początkowe hasło i opcjonalnie weryfikuje je w konsoli internetowej. `DiscoverSerialVia=AUTO` próbuje obsługiwanych ścieżek wykrywania; użyj `TargetSerial`, jeśli spis zasobów zawiera już numer seryjny.<sup>[[7]](#references)</sup>
```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```
Używaj wyniku wyłącznie do walidacji autoryzowanych zasobów. To, czy hasło zadziała, zależy od konkretnego modelu oraz, co najważniejsze, od tego, czy fabryczne hasło administratora zostało już zmienione.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Zautomatyzowane narzędzia do enumeracji / exploitation

| Narzędzie | Zastosowanie | Przykład |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Nadużycia PostScript/PJL/PCL, dostęp do systemu plików, sprawdzanie domyślnych poświadczeń, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Pobieranie konfiguracji (w tym książek adresowych i poświadczeń LDAP) przez HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Uruchamianie rogue authentication services oraz przechwytywanie/przekazywanie NetNTLM z callbacków SMB | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Wykrywanie numeru seryjnego, wyprowadzanie potencjalnego fabrycznego hasła administratora i weryfikowanie dostępu do konsoli webowej | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Hardening i wykrywanie

1. **Niezwłocznie instaluj poprawki / aktualizuj firmware** urządzeń MFP (sprawdzaj biuletyny PSIRT dostawcy).
2. **Zastępuj fabryczne hasła administratora** – sam firmware nie usuwa początkowych haseł wyprowadzanych z numeru seryjnego z wcześniej wyprodukowanych urządzeń Brother/OEM, których dotyczy problem.<sup>[[6]](#references)</sup>
3. **Konta usług z minimalnymi uprawnieniami** – nigdy nie używaj Domain Admin do LDAP/SMB/SMTP; ogranicz je do zakresów OU z dostępem *read-only*.
4. **Ogranicz dostęp zarządzający** – umieść interfejsy web/IPP/SNMP drukarki w sieci VLAN zarządzania lub za ACL/VPN.
5. **Ogranicz ruch wychodzący drukarki** – zezwalaj każdemu urządzeniu na komunikację wyłącznie z oczekiwanymi miejscami docelowymi DC/LDAP, poczty, DNS/NTP, druku i plików skanów. Pass-back wymaga callbacku do endpointu wybranego przez atakującego.
6. **Wyłącz nieużywane protokoły** – FTP, Telnet, raw-9100 oraz starsze szyfry SSL.
7. **Włącz logowanie audytowe** – niektóre urządzenia mogą wysyłać nieudane operacje LDAP/SMTP do sysloga; koreluj nieoczekiwane bindy.
8. **Monitoruj miejsca docelowe uwierzytelniania** – generuj alerty, gdy drukarka inicjuje połączenie LDAP, SMB, SMTP lub FTP z hostem spoza listy dozwolonych, szczególnie bezpośrednio po zalogowaniu do zarządzania lub zmianie konfiguracji.
9. **SNMPv3 lub wyłącz SNMP** – społeczność `public` często powoduje leak informacji o urządzeniu i numerze seryjnym.

---



---

## References

- [1] [To tylko drukarka… Co najgorszego może się wydarzyć?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Drukarka wielofunkcyjna Xerox Versalink C7025: podatności związane z atakiem Pass-Back (naprawione)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [Łagodzenie/naprawa podatności CP2025-004 dotyczącej drukarek produkcyjnych, wielofunkcyjnych drukarek biurowych/domowych oraz drukarek laserowych](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Uzyskiwanie poświadczeń domenowych przez drukarkę za pomocą Netcata](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploitation wielofunkcyjnych drukarek podczas pentestingu](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Wiele urządzeń Brother: wiele podatności (NAPRAWIONE)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: moduł obejścia uwierzytelniania domyślnego administratora Brother](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
