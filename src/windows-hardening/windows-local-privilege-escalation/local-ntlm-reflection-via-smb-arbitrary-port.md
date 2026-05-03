# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

최근 Windows build에는 **대체 TCP port에 대한 SMB client support**가 도입되었습니다. 이 기능은 공격자가 다음을 할 수 있을 때 **local NTLM authentication**을 **SYSTEM local privilege escalation**으로 악용할 수 있습니다:

1. **non-445 port**의 attacker-controlled listener로 SMB connection을 연다
2. 그 TCP connection을 살아 있게 유지한다
3. **privileged local client**가 **같은 SMB share path**에 접근하도록 coerce한다
4. 발생한 **local NTLM authentication**을 machine의 실제 SMB service로 relay한다

이것이 **CVE-2026-24294** 뒤에 있는 primitive이며, **March 2026**에 patched 되었습니다.

## Why it works

이전의 CMTI / serialized-SPN reflection trick은 여기에서 다룹니다:

{{#ref}}
../ntlm/README.md
{{#endref}}

이 새로운 variant는 marshalled hostname이 필요하지 않습니다. 대신 두 가지 SMB client behavior를 악용합니다:

- **Windows 11 24H2** 및 **Windows Server 2025**에서 제공되는 **Alternative port support**, `net use \\host\share /tcpport:<port>`로 사용 가능
- 여러 authenticated session이 같은 TCP connection을 공유할 수 있는 **SMB connection reuse / multiplexing**

즉, low-privileged user가 먼저 SMB client에서 attacker SMB server의 high port로 TCP connection을 만들고, 그 다음 privileged service가 **정확히 같은 UNC path**에 접근하도록 coerce할 수 있습니다. Windows가 기존 TCP connection을 재사용하기로 결정하면, privileged NTLM exchange는 attacker-controlled transport를 통해 전송되고 local SMB server로 relay될 수 있습니다.

## Preconditions

- Target가 SMB alternative ports를 지원해야 함:
- **Windows 11 24H2** 또는 이후 버전
- **Windows Server 2025** 또는 이후 버전
- 공격자가 선택한 high port에서 local 또는 remote SMB server를 실행할 수 있어야 함
- 공격자가 privileged service를 UNC path에 접근하도록 coerce할 수 있어야 함
- privileged authentication은 반드시 **NTLM local authentication**이어야 함
- Target가 relay 가능해야 함:
- Synacktiv는 이것이 **Windows Server 2025**에서 기본적으로 동작한다고 보고함
- 그들의 chain은 **Windows 11 24H2**에서는 동작하지 않았는데, 그 이유는 outbound SMB signing이 기본적으로 강제되기 때문임

## Userland and internals

명령줄에서 보면 이 기능은 단순해 보입니다:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmatically, client는 문서화되지 않은 `lpUseOptions` 데이터를 사용해 `WNetAddConnection4W`를 사용합니다. 관련 옵션은 `TraP`(transport parameters)이며, 이는 결국 FSCTL을 통해 kernel SMB client에 도달하고 `mrxsmb`에 의해 파싱됩니다.

중요한 실무 참고사항:

- **UNC syntax에는 여전히 port field가 없음**
- **`net use`는 per-logon-session임**
- 이 bypass는 **TCP connection과 SMB session이 별도 객체**이기 때문에 계속 동작함
- exploit이 SMB client가 이전에 생성된 TCP connection을 재사용하는 것에 의존한다면, **같은 share path를 재사용하는 것**이 필수임

## Exploitation flow

### 1. Create the attacker-controlled SMB transport

고포트에서 SMB server를 실행하고 Windows가 거기에 connect하도록 만드세요:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
서버는 사용자가 제어하는 임의의 credential pair를 받을 수 있습니다. 예를 들어 `user:user` 입니다. 이 단계의 목표는 아직 privilege escalation이 아니라, Windows SMB client가 당신의 listener에 대해 재사용 가능한 TCP connection을 열고 유지하게 만드는 것입니다.

### 2. privileged service를 같은 UNC path로 coercion하기

**PetitPotam** 같은 coercion primitive를 **같은** `\\192.168.56.3\share` path에 대해 사용하세요. coercion된 client가 privileged이고 target name이 local(`localhost` 또는 local IP/host)이라면, Windows는 **NTLM local authentication**을 수행합니다.

TCP connection이 재사용되기 때문에, 그 privileged NTLM exchange는 실제 local SMB server가 아니라 attacker SMB service로 전송됩니다.

### 3. privileged authentication을 local SMB로 relay하기

attacker-controlled SMB service는 캡처한 privileged NTLM exchange를 `ntlmrelayx.py`로 전달하고, `ntlmrelayx.py`는 이를 machine의 실제 SMB listener로 relay하여 `NT AUTHORITY\SYSTEM` 세션을 획득합니다.

공개 writeup에서 흔히 쓰인 도구:

- 재사용된 TCP connection을 통해 privileged auth를 받기 위한 custom port의 `smbserver.py`
- 캡처한 NTLM을 local SMB로 relay하기 위한 `ntlmrelayx.py`
- privileged authentication을 강제하기 위한 `PetitPotam.exe` 또는 다른 coercion primitive

## Operator notes

- 이것은 generic remote relay trick이 아니라 **local privilege escalation** technique입니다
- attacker-controlled SMB service는 원래 share mount에 사용된 **같은 TCP connection**에서 privileged authentication을 처리해야 합니다
- coercion된 접근이 **다른 share path**에 닿으면 Windows가 다른 connection을 만들 수 있고, chain이 끊깁니다
- SMB signing 요구사항은 arbitrary-port 단계가 동작하더라도 relay를 막을 수 있습니다
- Kerberos material만 있거나 local NTLM을 강제할 수 없다면, 이 exact variant는 충분하지 않습니다

## Detection and hardening

- **March 2026 Patch Tuesday**의 **CVE-2026-24294**를 패치하세요
- **non-default SMB ports**를 사용하는 `net use` 또는 `New-SmbMapping`을 모니터링하세요
- 워크스테이션이나 서버에서 **high TCP ports**로 나가는 비정상적인 outbound SMB를 경고하세요
- **EFSRPC / PetitPotam-style** trigger 같은 coercion opportunities를 검토하세요
- 가능한 경우 SMB signing을 강제하세요; Synacktiv는 이것이 Windows 11 24H2에서 relay를 막았다고 명시했습니다

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
