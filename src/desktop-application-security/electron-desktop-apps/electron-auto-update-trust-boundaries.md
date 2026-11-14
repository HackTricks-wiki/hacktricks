# Electron Auto-Update 신뢰 경계

{{#include ../../banners/hacktricks-training.md}}

## Electron 자동 업데이트 공격 표면

업데이터를 원격 코드 실행 경계로 취급하세요. 업데이터는 실행 가능한 콘텐츠를 가져와 해당 콘텐츠가 더 최신이고 신뢰할 수 있는지 판단하고, 로컬에 저장한 다음 설치 프로그램에 전달합니다. 최종 `.app`에 서명되어 있는지만 확인하지 말고 릴리스 인덱스, 버전별 메타데이터, artifact, detached signature, 내장된 검증 키, 캐시, 임시 경로, 설치 프로그램을 포함한 전체 신뢰 그래프를 검토하세요.<sup>[[1]](#references)[[2]](#references)</sup>

### 가치가 높은 테스트

- **Rollback/replay:** 이전에 유효했던 manifest와 아직 서명된 artifact를 다시 전송해 보세요. 서명은 입력의 진위를 인증하지만 최신성은 보장하지 않습니다. 클라이언트는 인증된 복구 정책이 롤백을 명시적으로 허용하지 않는 한, 영구적인 단조 증가 하한보다 낮은 버전을 거부해야 합니다.<sup>[[2]](#references)</sup>
- **메타데이터/artifact 대체:** 버전, URL, 예상 hash, artifact, detached signature를 각각 독립적으로 변경해 보세요. 또한 한 릴리스의 유효한 artifact/signature 쌍을 다른 릴리스의 메타데이터와 조합해 보세요. 릴리스 메타데이터에 서명이 없으면 TLS나 최종 실행 파일의 서명만으로는 침해된 origin/CDN이 선택 로직을 변경하는 것을 막을 수 없습니다.<sup>[[1]](#references)[[2]](#references)</sup>
- **서명된 채널 혼동:** 정식으로 서명된 alpha, beta, development 또는 debug 빌드를 production feed를 통해 제공해 보세요. 환경 간에 동일한 키와 정책을 재사용하면 서명자만 확인하는 검사를 artifact가 통과할 수 있습니다. production의 ID/채널을 인증된 정책에 포함하거나 별도의 trust root를 사용해야 합니다.<sup>[[2]](#references)</sup>
- **임시 파일 TOCTOU:** 검증 과정에서 경로를 열고 설치 과정에서 나중에 같은 경로를 다시 여는지 확인하세요. 로컬 공격자가 두 작업 사이에 저장된 객체의 이름을 바꾸거나, 교체하거나, 경로를 다른 곳으로 돌릴 수 있다면 설치 프로그램이 검증되지 않은 바이트를 사용할 수 있습니다. mode-`0700` 스테이징 디렉터리는 접근을 제한하지만 두 작업을 원자적으로 처리하지는 않습니다.<sup>[[2]](#references)</sup>

정적 분석과 런타임 분석을 통해 이러한 경계를 빠르게 찾을 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

승인된 테스트 중 업데이트 확인 요청을 가로채고, 모든 응답을 보관한 뒤 한 번에 하나씩 필드를 변경하세요. 그런 다음 staging directory의 소유권과 모드를 확인하고 다운로드부터 설치까지 파일 열기 동작을 추적하세요. macOS에서 이 흐름이 권한이 높은 helper에 도달하면 [installer trust-boundary testing](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md)을 진행하고, “signed”를 완전한 신원 확인으로 간주하지 말고 [code-signing weaknesses](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md)를 검토하세요.<sup>[[2]](#references)</sup>

### 예상되는 바인딩 및 정책

방어 가능한 설계는 선택 메타데이터와 artifact 바이트 모두를 인증합니다. SafeUpdater 참조 설계는 내장된 Ed25519 공개 키, 서명된 manifest와 artifact, `SHA-256(file)` 및 버전에서 파생한 서명된 메시지, 그리고 서명된 메타데이터에 저장된 SHA-512 artifact digest를 보여줍니다. 이 설계는 명시적으로 연구용 참조 자료이며 프로덕션에 바로 사용할 수 있는 패키지가 아닙니다.<sup>[[1]](#references)[[2]](#references)</sup>

대상 시스템이 다음 속성도 제공하는지 확인하세요.<sup>[[1]](#references)[[2]](#references)</sup>

- artifact digest를 표준 버전 및 릴리스 환경에 바인딩하는 모호하지 않은 서명 표현을 사용합니다.
- 기본적으로 downgrade를 비활성화하고, 승인된 rollback에 대해 최소 허용 버전을 적용합니다.
- 별도의 키/채널 또는 인증된 릴리스 정책 데이터를 통해 production과 non-production을 분리합니다.
- 동일한 경로명을 다시 확인하는 대신 이미 검증된 열린 파일(또는 이에 상응하는 불변 핸들/객체)을 설치합니다.

## References

- [1] [Doyensec ElectronSafeUpdater 참조 구현](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater: 안전한 Electron 자동 업데이트 메커니즘 설계](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
