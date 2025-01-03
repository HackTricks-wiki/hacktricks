{{#include ../../banners/hacktricks-training.md}}

W Internecie znajduje się kilka blogów, które **podkreślają niebezpieczeństwa związane z pozostawianiem drukarek skonfigurowanych z LDAP z domyślnymi/słabymi** danymi logowania.\
Dzieje się tak, ponieważ atakujący może **oszukać drukarkę, aby uwierzytelniła się w fałszywym serwerze LDAP** (zwykle `nc -vv -l -p 444` wystarczy) i przechwycić **dane logowania drukarki w postaci czystego tekstu**.

Ponadto, wiele drukarek zawiera **dzienniki z nazwami użytkowników** lub może nawet być w stanie **pobierać wszystkie nazwy użytkowników** z kontrolera domeny.

Wszystkie te **wrażliwe informacje** oraz powszechny **brak zabezpieczeń** sprawiają, że drukarki są bardzo interesujące dla atakujących.

Kilka blogów na ten temat:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Konfiguracja drukarki

- **Lokalizacja**: Lista serwerów LDAP znajduje się w: `Network > LDAP Setting > Setting Up LDAP`.
- **Zachowanie**: Interfejs pozwala na modyfikacje serwera LDAP bez ponownego wprowadzania danych logowania, co ma na celu wygodę użytkownika, ale stwarza ryzyko bezpieczeństwa.
- **Eksploatacja**: Eksploatacja polega na przekierowaniu adresu serwera LDAP do kontrolowanej maszyny i wykorzystaniu funkcji "Test Connection" do przechwycenia danych logowania.

## Przechwytywanie danych logowania

**Aby uzyskać bardziej szczegółowe kroki, zapoznaj się z oryginalnym [źródłem](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Metoda 1: Nasłuchiwacz Netcat

Prosty nasłuchiwacz netcat może wystarczyć:
```bash
sudo nc -k -v -l -p 386
```
Jednak sukces tej metody jest różny.

### Metoda 2: Pełny serwer LDAP z Slapd

Bardziej niezawodne podejście polega na skonfigurowaniu pełnego serwera LDAP, ponieważ drukarka wykonuje null bind, a następnie zapytanie przed próbą powiązania poświadczeń.

1. **Konfiguracja serwera LDAP**: Przewodnik opiera się na krokach z [tego źródła](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Kluczowe kroki**:
- Zainstaluj OpenLDAP.
- Skonfiguruj hasło administratora.
- Importuj podstawowe schematy.
- Ustaw nazwę domeny w bazie danych LDAP.
- Skonfiguruj LDAP TLS.
3. **Wykonanie usługi LDAP**: Po skonfigurowaniu, usługę LDAP można uruchomić za pomocą:
```bash
slapd -d 2
```
## Odniesienia

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)

{{#include ../../banners/hacktricks-training.md}}
