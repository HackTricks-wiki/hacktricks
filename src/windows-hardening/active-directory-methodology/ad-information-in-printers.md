# Informacje w drukarkach

{{#include ../../banners/hacktricks-training.md}}

W Internecie znajduje się kilka blogów, które **podkreślają zagrożenia związane z pozostawianiem drukarek skonfigurowanych z LDAP i domyślnymi/słabymi** danymi logowania.  \
Dzieje się tak, ponieważ atakujący może **nakłonić drukarkę do uwierzytelnienia się względem złośliwego serwera LDAP** (zwykle wystarczy `nc -vv -l -p 389` lub `slapd -d 2`) i przechwycić **poświadczenia drukarki w postaci jawnego tekstu**.

Ponadto wiele drukarek zawiera **logi z nazwami użytkowników** lub może nawet umożliwiać **pobranie wszystkich nazw użytkowników** z kontrolera domeny.

Wszystkie te **wrażliwe informacje** oraz powszechny **brak zabezpieczeń** sprawiają, że drukarki są bardzo interesujące dla atakujących.

Kilka wprowadzających wpisów na ten temat:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Konfiguracja drukarki

- **Lokalizacja**: Lista serwerów LDAP zwykle znajduje się w interfejsie webowym (np. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Zachowanie**: Wiele wbudowanych serwerów webowych umożliwia modyfikowanie serwerów LDAP **bez ponownego wprowadzania danych logowania** (funkcja zwiększająca wygodę użytkowania → zagrożenie bezpieczeństwa).
- **Eksploitacja**: Przekieruj adres serwera LDAP na hosta kontrolowanego przez atakującego i użyj przycisku *Test Connection* / *Address Book Sync*, aby wymusić na drukarce wykonanie bindowania do tego hosta.

---

## Przechwytywanie poświadczeń

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Małe/stare urządzenia wielofunkcyjne mogą wysyłać prosty *simple-bind* jawnym tekstem, który netcat może przechwycić. Nowoczesne urządzenia zwykle najpierw wykonują zapytanie anonimowe, a następnie próbują wykonać bind, dlatego wyniki mogą się różnić.<sup>[[1]](#references)</sup>

### Metoda 2 – Pełny Rogue LDAP server (zalecane)

Ponieważ wiele urządzeń wykona anonimowe wyszukiwanie *przed* uwierzytelnieniem, uruchomienie rzeczywistego demona LDAP zapewnia znacznie bardziej niezawodne wyniki:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Gdy drukarka wykona lookup, w debug output zobaczysz credentials w clear text.

> 💡  Możesz również użyć `impacket/examples/ldapd.py` (Python rogue LDAP) lub `Responder -w -r -f`, aby harvestować hashe NTLMv2 przez LDAP/SMB.

---

## Recent Pass-Back Vulnerabilities (2024-2025)

Pass-back to *nie* problem teoretyczny – vendorzy nadal publikują advisories w 2024/2025, które dokładnie opisują tę klasę ataków.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 urządzeń Xerox VersaLink C70xx MFP pozwalał uwierzytelnionemu adminowi (lub dowolnej osobie, gdy pozostawiono domyślne credentials) na:

* **CVE-2024-12510 – LDAP pass-back**: zmianę adresu serwera LDAP i wywołanie lookup, co powodowało, że urządzenie leakowało skonfigurowane Windows credentials do hosta kontrolowanego przez atakującego.
* **CVE-2024-12511 – SMB/FTP pass-back**: identyczny problem za pośrednictwem miejsc docelowych *scan-to-folder*, prowadzący do wycieku credentials NetNTLMv2 lub FTP w clear text.<sup>[[2]](#references)</sup>

Prosty listener, taki jak:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
lub nieuczciwy serwer SMB (`impacket-smbserver`) wystarczy do przechwycenia poświadczeń.

### Canon imageRUNNER / imageCLASS – advisory z 20 maja 2025 r.

Canon potwierdził słabość **SMTP/LDAP pass-back** w dziesiątkach linii produktów Laser i MFP. Atakujący z dostępem administratora może zmodyfikować konfigurację serwera i pobrać zapisane poświadczenia LDAP **lub** SMTP (wiele organizacji używa uprzywilejowanego konta, aby umożliwić skanowanie do poczty).<sup>[[3]](#references)</sup>

Wytyczne producenta wyraźnie zalecają:

1. Jak najszybszą aktualizację do załatanego firmware, gdy tylko będzie dostępny.
2. Używanie silnych, unikalnych haseł administratora.
3. Unikanie uprzywilejowanych kont AD podczas integracji drukarek.

---

## Narzędzia do automatycznej enumeracji / exploitation

| Narzędzie | Zastosowanie | Przykład |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Nadużycia PostScript/PJL/PCL, dostęp do systemu plików, sprawdzanie domyślnych poświadczeń, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Pobieranie konfiguracji (w tym książek adresowych i poświadczeń LDAP) przez HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Przechwytywanie i przekazywanie hashy NetNTLM z mechanizmu SMB/FTP pass-back | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Lekka usługa rogue LDAP do odbierania bindów w postaci jawnego tekstu | `python ldapd.py -debug` |

---

## Hardening i wykrywanie

1. **Niezwłocznie instaluj poprawki / aktualizuj firmware** urządzeń MFP (sprawdzaj biuletyny PSIRT producenta).
2. **Konta usługowe z minimalnymi uprawnieniami** – nigdy nie używaj Domain Admin do LDAP/SMB/SMTP; ogranicz je do zakresów OU z dostępem *read-only*.
3. **Ogranicz dostęp zarządzający** – umieść interfejsy web/IPP/SNMP drukarek w VLAN-ie zarządzającym lub za ACL/VPN.
4. **Wyłącz nieużywane protokoły** – FTP, Telnet, raw-9100 oraz starsze szyfry SSL.
5. **Włącz rejestrowanie audytowe** – niektóre urządzenia mogą wysyłać do syslog informacje o błędach LDAP/SMTP; koreluj nieoczekiwane bindy.
6. **Monitoruj bindy LDAP w postaci jawnego tekstu** z nietypowych źródeł (drukarki powinny normalnie komunikować się wyłącznie z kontrolerami domeny).
7. **SNMPv3 lub wyłącz SNMP** – community `public` często ujawnia konfigurację urządzenia i LDAP.

---

## Referencje

- [1] [To tylko drukarka… Co najgorszego może się wydarzyć?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Drukarka wielofunkcyjna Xerox Versalink C7025: podatności na atak pass-back (naprawione)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004: ograniczanie / usuwanie podatności w drukarkach produkcyjnych, wielofunkcyjnych drukarkach biurowych / do małych biur oraz drukarkach laserowych](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Uzyskiwanie poświadczeń domenowych przez drukarkę za pomocą Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting Multifunction Printers During A Penetration Test Engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
