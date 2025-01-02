# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): 각 프로세스가 생성하는 모든 연결을 모니터링합니다. 모드에 따라 (조용히 연결 허용, 조용히 연결 거부 및 경고) 새로운 연결이 설정될 때마다 **경고를 표시**합니다. 이 모든 정보를 볼 수 있는 매우 멋진 GUI도 있습니다.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See 방화벽. 의심스러운 연결에 대해 경고하는 기본 방화벽입니다 (GUI가 있지만 Little Snitch의 것만큼 화려하지는 않습니다).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): **악성코드가 지속될 수 있는** 여러 위치를 검색하는 Objective-See 애플리케이션입니다 (일회성 도구로, 모니터링 서비스가 아닙니다).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): KnockKnock처럼 지속성을 생성하는 프로세스를 모니터링합니다.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): 키보드 "이벤트 탭"을 설치하는 **키로거**를 찾기 위한 Objective-See 애플리케이션입니다. 

{{#include ../../banners/hacktricks-training.md}}
