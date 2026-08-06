# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

최근 Windows 빌드에는 **대체 TCP 포트에 대한 SMB client support**가 도입되었습니다. 이 기능은 다음 조건에서 **local NTLM authentication**을 **SYSTEM local privilege escalation**으로 전환하는 데 악용될 수 있습니다:<sup>[[1]](#references)</sup>

1. **445가 아닌 포트**에서 attacker-controlled listener로 SMB connection을 엽니다.
2. 해당 TCP connection을 유지합니다.
3. **privileged local client**가 **동일한 SMB share path**에 액세스하도록 유도합니다.
4. 그 결과 발생한 **local NTLM authentication**을 시스템의 실제 SMB service로 다시 relay합니다.

이것은 **CVE-2026-24294**의 기반이 되는 primitive이며, **March 2026**에 patch되었습니다.<sup>[[1]](#references)[[4]](#references)</sup>

## Why it works

이전의 CMTI / serialized-SPN reflection trick은 여기에서 다룹니다:

{{#ref}}
../ntlm/README.md
{{#endref}}

이 새로운 variant에는 marshalled hostname이 필요하지 않습니다. 대신 두 가지 SMB client behaviour를 악용합니다:<sup>[[1]](#references)</sup>

- **Windows 11 24H2** 및 **Windows Server 2025**에서 지원되는 **Alternative port support**. 사용자는 `net use \\host\share /tcpport:<port>`를 통해 이를 사용할 수 있습니다.
- 여러 authenticated session이 동일한 TCP connection을 사용할 수 있는 **SMB connection reuse / multiplexing**

따라서 low-privileged user는 먼저 SMB client에서 attacker SMB server로 향하는 TCP connection을 high port에서 생성한 다음, privileged service가 **정확히 동일한 UNC path**에 액세스하도록 유도할 수 있습니다. Windows가 기존 TCP connection을 재사용하기로 결정하면 privileged NTLM exchange가 attacker-controlled transport를 통해 전송되며, 이를 local SMB server로 relay할 수 있습니다.<sup>[[1]](#references)</sup>

## Preconditions

- Target이 SMB alternative ports를 지원해야 합니다:<sup>[[2]](#references)</sup>
- **Windows 11 24H2** 이상
- Attacker가 선택한 high port에서 local 또는 remote SMB server를 실행할 수 있어야 합니다.
- Attacker가 privileged service가 UNC path에 액세스하도록 유도할 수 있어야 합니다.
- Privileged authentication은 **NTLM local authentication**이어야 합니다.
- Target이 relay 가능해야 합니다:<sup>[[1]](#references)</sup>
- Synacktiv는 **Windows Server 2025**에서 기본 설정으로 동작한다고 보고했습니다.
- 해당 chain은 **Windows 11 24H2**에서는 기본적으로 outbound SMB signing이 강제되기 때문에 동작하지 않았습니다.

## Userland and internals

Command line에서 이 기능은 간단해 보입니다:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmatically, client는 undocumented `lpUseOptions` data와 함께 `WNetAddConnection4W`를 사용합니다. 관련 옵션은 `TraP`(transport parameters)이며, 이는 결국 FSCTL을 통해 kernel SMB client에 도달하고 `mrxsmb`에서 parsing됩니다.<sup>[[1]](#references)[[3]](#references)</sup>

중요한 practical notes:<sup>[[1]](#references)</sup>

- **UNC syntax에는 여전히 port field가 없음**
- **`net use`는 logon session별로 적용됨**
- **TCP connection과 SMB session은 서로 별개의 object이므로 bypass가 여전히 작동함**
- exploit이 SMB client가 previously created TCP connection을 재사용하는 것에 의존한다면 **동일한 share path를 재사용해야 함**

## Exploitation flow

### 1. Attacker-controlled SMB transport 생성

high port에서 SMB server를 실행하고 Windows가 해당 server에 connect하도록 합니다:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
서버는 사용자가 제어하는 임의의 credential pair를 허용할 수 있습니다. 예를 들어 `user:user`를 사용할 수 있습니다. 이 단계의 목표는 아직 privilege escalation이 아니라, Windows SMB client가 listener에 대한 재사용 가능한 TCP connection을 열고 유지하도록 만드는 것입니다.<sup>[[1]](#references)</sup>

### 2. privileged service를 동일한 UNC path로 강제

**PetitPotam**과 같은 coercion primitive를 **동일한** `\\192.168.56.3\share` path에 대해 사용합니다. coerced client가 privileged 상태이고 target name이 local(`localhost` 또는 local IP/host)이면, Windows는 **NTLM local authentication**을 수행합니다.

TCP connection이 재사용되므로, privileged NTLM exchange는 실제 local SMB server로 직접 전달되지 않고 attacker SMB service로 전달됩니다.<sup>[[1]](#references)</sup>

### 3. privileged authentication을 local SMB로 relay

attacker-controlled SMB service는 privileged NTLM exchange를 `ntlmrelayx.py`로 전달하고, `ntlmrelayx.py`는 이를 해당 시스템의 실제 SMB listener로 relay하여 `NT AUTHORITY\SYSTEM` 권한의 session을 획득합니다.<sup>[[1]](#references)</sup>

공개 writeup에 사용된 일반적인 tooling:<sup>[[1]](#references)</sup>

- 재사용된 TCP connection을 통해 privileged auth를 수신하도록 custom port에서 실행하는 `smbserver.py`
- 캡처된 NTLM을 local SMB로 relay하는 `ntlmrelayx.py`
- privileged authentication을 강제로 수행시키는 `PetitPotam.exe` 또는 다른 coercion primitive

## Operator notes

- 이는 일반적인 remote relay trick이 아닌 **local privilege escalation** technique입니다<sup>[[1]](#references)</sup>
- attacker-controlled SMB service는 원래 share mount에 사용된 **동일한 TCP connection**에서 privileged authentication을 처리해야 합니다<sup>[[1]](#references)</sup>
- coerced access가 **다른 share path**에 도달하면 Windows가 다른 connection을 설정할 수 있으며, 이 경우 chain이 중단됩니다<sup>[[1]](#references)</sup>
- arbitrary-port 단계가 작동하더라도 SMB signing requirements가 relay를 차단할 수 있습니다<sup>[[1]](#references)</sup>
- Kerberos material만 보유하고 있거나 local NTLM을 강제로 수행시킬 수 없다면, 이 exact variant만으로는 충분하지 않습니다<sup>[[1]](#references)</sup>

## Detection and hardening

- **March 2026 Patch Tuesday**에서 제공된 **CVE-2026-24294** patch를 적용합니다<sup>[[4]](#references)</sup>
- **non-default SMB ports**를 사용하는 `net use` 또는 `New-SmbMapping`을 모니터링합니다<sup>[[1]](#references)</sup>
- workstation 또는 server에서 **high TCP ports**로 전송되는 비정상적인 outbound SMB를 alert합니다<sup>[[1]](#references)</sup>
- **EFSRPC / PetitPotam-style** trigger와 같은 coercion 기회를 검토합니다<sup>[[1]](#references)</sup>
- 가능한 경우 SMB signing을 적용합니다. Synacktiv는 이것이 Windows 11 24H2에서 relay를 차단했다고 구체적으로 언급했습니다<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
