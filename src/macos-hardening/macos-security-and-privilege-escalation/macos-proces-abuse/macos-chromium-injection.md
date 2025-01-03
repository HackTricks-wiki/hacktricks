# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

Chromium 기반 브라우저는 Google Chrome, Microsoft Edge, Brave 등입니다. 이러한 브라우저는 Chromium 오픈 소스 프로젝트를 기반으로 구축되었으며, 따라서 공통의 기반을 공유하고 유사한 기능 및 개발자 옵션을 가지고 있습니다.

#### `--load-extension` 플래그

`--load-extension` 플래그는 명령줄이나 스크립트에서 Chromium 기반 브라우저를 시작할 때 사용됩니다. 이 플래그는 브라우저 시작 시 **하나 이상의 확장 프로그램을 자동으로 로드**할 수 있게 해줍니다.

#### `--use-fake-ui-for-media-stream` 플래그

`--use-fake-ui-for-media-stream` 플래그는 Chromium 기반 브라우저를 시작하는 데 사용할 수 있는 또 다른 명령줄 옵션입니다. 이 플래그는 **카메라와 마이크로폰의 미디어 스트림에 접근하기 위한 권한을 요청하는 일반 사용자 프롬프트를 우회**하도록 설계되었습니다. 이 플래그가 사용되면 브라우저는 카메라나 마이크로폰에 대한 접근을 요청하는 모든 웹사이트나 애플리케이션에 자동으로 권한을 부여합니다.

### 도구

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### 예시
```bash
# Intercept traffic
voodoo intercept -b chrome
```
더 많은 예시는 도구 링크에서 찾을 수 있습니다.

## 참고문헌

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
