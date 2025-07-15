# Informacje w drukarkach

{{#include ../../banners/hacktricks-training.md}}

Istnieje kilka blogów w Internecie, które **podkreślają niebezpieczeństwa związane z pozostawieniem drukarek skonfigurowanych z LDAP z domyślnymi/słabymi** danymi logowania.  \
Dzieje się tak, ponieważ atakujący może **oszukać drukarkę, aby uwierzytelniła się w fałszywym serwerze LDAP** (zazwyczaj `nc -vv -l -p 389` lub `slapd -d 2` wystarczy) i przechwycić **dane logowania drukarki w postaci niezaszyfrowanej**.

Ponadto, wiele drukarek będzie zawierać **logi z nazwami użytkowników** lub może nawet być w stanie **pobierać wszystkie nazwy użytkowników** z kontrolera domeny.

Wszystkie te **wrażliwe informacje** oraz powszechny **brak bezpieczeństwa** sprawiają, że drukarki są bardzo interesujące dla atakujących.

Kilka wprowadzających blogów na ten temat:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

---
## Konfiguracja drukarki

- **Lokalizacja**: Lista serwerów LDAP zazwyczaj znajduje się w interfejsie webowym (np. *Sieć ➜ Ustawienia LDAP ➜ Konfiguracja LDAP*).
- **Zachowanie**: Wiele wbudowanych serwerów webowych pozwala na modyfikacje serwera LDAP **bez ponownego wprowadzania danych logowania** (funkcja użyteczności → ryzyko bezpieczeństwa).
- **Eksploatacja**: Przekieruj adres serwera LDAP na host kontrolowany przez atakującego i użyj przycisku *Testuj połączenie* / *Synchronizacja książki adresowej*, aby zmusić drukarkę do połączenia z tobą.

---
## Przechwytywanie danych logowania

### Metoda 1 – Nasłuchiwacz Netcat
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Małe/stare MFP mogą wysyłać prosty *simple-bind* w czystym tekście, który netcat może przechwycić. Nowoczesne urządzenia zazwyczaj najpierw wykonują anonimowe zapytanie, a następnie próbują się uwierzytelnić, więc wyniki się różnią.

### Metoda 2 – Pełny serwer LDAP typu Rogue (zalecane)

Ponieważ wiele urządzeń wyda anonimowe zapytanie *przed* uwierzytelnieniem, uruchomienie prawdziwego demona LDAP daje znacznie bardziej wiarygodne wyniki:
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Kiedy drukarka wykonuje swoje zapytanie, zobaczysz hasła w postaci czystego tekstu w wyjściu debugowania.

> 💡  Możesz również użyć `impacket/examples/ldapd.py` (Python rogue LDAP) lub `Responder -w -r -f`, aby zbierać hashe NTLMv2 przez LDAP/SMB.

---
## Ostatnie luki w zabezpieczeniach Pass-Back (2024-2025)

Pass-back *nie* jest teoretycznym problemem – dostawcy wciąż publikują ostrzeżenia w 2024/2025, które dokładnie opisują tę klasę ataków.

### Xerox VersaLink – CVE-2024-12510 i CVE-2024-12511

Oprogramowanie układowe ≤ 57.69.91 drukarek Xerox VersaLink C70xx MFP pozwalało uwierzytelnionemu administratorowi (lub każdemu, gdy domyślne dane logowania pozostają) na:

* **CVE-2024-12510 – LDAP pass-back**: zmianę adresu serwera LDAP i wywołanie zapytania, co powoduje, że urządzenie ujawnia skonfigurowane dane logowania Windows do hosta kontrolowanego przez atakującego.
* **CVE-2024-12511 – SMB/FTP pass-back**: identyczny problem przez *scan-to-folder* destynacje, ujawniając NetNTLMv2 lub hasła FTP w postaci czystego tekstu.

Prosty nasłuchiwacz, taki jak:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
or serwer SMB (`impacket-smbserver`) wystarczy, aby zebrać dane uwierzytelniające.

### Canon imageRUNNER / imageCLASS – Zawiadomienie 20 maja 2025

Canon potwierdził słabość **SMTP/LDAP pass-back** w dziesiątkach linii produktów Laser & MFP. Atakujący z dostępem administratora może zmodyfikować konfigurację serwera i odzyskać przechowywane dane uwierzytelniające dla LDAP **lub** SMTP (wiele organizacji używa uprzywilejowanego konta, aby umożliwić skanowanie do poczty).

Zalecenia producenta wyraźnie sugerują:

1. Aktualizację do poprawionego oprogramowania układowego, gdy tylko będzie dostępne.
2. Używanie silnych, unikalnych haseł administratora.
3. Unikanie uprzywilejowanych kont AD do integracji z drukarkami.

---
## Narzędzia do automatycznej enumeracji / eksploatacji

| Narzędzie | Cel | Przykład |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Nadużycie PostScript/PJL/PCL, dostęp do systemu plików, sprawdzenie domyślnych danych uwierzytelniających, *odkrywanie SNMP* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Zbieranie konfiguracji (w tym książek adresowych i danych uwierzytelniających LDAP) przez HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Przechwytywanie i przekazywanie skrótów NetNTLM z pass-back SMB/FTP | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Lekka usługa LDAP do odbierania połączeń w czystym tekście | `python ldapd.py -debug` |

---
## Utwardzanie i wykrywanie

1. **Szybka aktualizacja / aktualizacja oprogramowania układowego** MFP (sprawdź biuletyny PSIRT producenta).
2. **Konta serwisowe z minimalnymi uprawnieniami** – nigdy nie używaj konta Domain Admin do LDAP/SMB/SMTP; ogranicz do *tylko do odczytu* zakresów OU.
3. **Ogranicz dostęp do zarządzania** – umieść interfejsy web/IPP/SNMP drukarek w VLAN zarządzającym lub za ACL/VPN.
4. **Wyłącz nieużywane protokoły** – FTP, Telnet, raw-9100, starsze szyfry SSL.
5. **Włącz rejestrowanie audytów** – niektóre urządzenia mogą rejestrować błędy LDAP/SMTP w syslog; skoreluj niespodziewane połączenia.
6. **Monitoruj połączenia LDAP w czystym tekście** z nietypowych źródeł (drukarki powinny normalnie komunikować się tylko z DC).
7. **SNMPv3 lub wyłącz SNMP** – społeczność `public` często ujawnia konfigurację urządzenia i LDAP.

---
## Odniesienia

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)
- Rapid7. “Xerox VersaLink C7025 MFP Pass-Back Attack Vulnerabilities.” Luty 2025.
- Canon PSIRT. “Mitigacja podatności przeciwko SMTP/LDAP Passback dla drukarek laserowych i małych wielofunkcyjnych drukarek biurowych.” Maj 2025.

{{#include ../../banners/hacktricks-training.md}}
