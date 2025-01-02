{{#include ../../banners/hacktricks-training.md}}

## 펌웨어 무결성

**사용자 정의 펌웨어 및/또는 컴파일된 바이너리는 무결성 또는 서명 검증 결함을 악용하기 위해 업로드될 수 있습니다**. 백도어 바인드 셸 컴파일을 위해 다음 단계를 따를 수 있습니다:

1. 펌웨어는 firmware-mod-kit (FMK)를 사용하여 추출할 수 있습니다.
2. 대상 펌웨어 아키텍처와 엔디안 형식을 식별해야 합니다.
3. Buildroot 또는 환경에 적합한 다른 방법을 사용하여 크로스 컴파일러를 구축할 수 있습니다.
4. 크로스 컴파일러를 사용하여 백도어를 구축할 수 있습니다.
5. 백도어는 추출된 펌웨어의 /usr/bin 디렉토리에 복사할 수 있습니다.
6. 적절한 QEMU 바이너리는 추출된 펌웨어의 rootfs에 복사할 수 있습니다.
7. chroot와 QEMU를 사용하여 백도어를 에뮬레이트할 수 있습니다.
8. netcat을 통해 백도어에 접근할 수 있습니다.
9. QEMU 바이너리는 추출된 펌웨어의 rootfs에서 제거해야 합니다.
10. 수정된 펌웨어는 FMK를 사용하여 재패키징할 수 있습니다.
11. 백도어가 있는 펌웨어는 펌웨어 분석 툴킷 (FAT)으로 에뮬레이트하고 netcat을 사용하여 대상 백도어 IP와 포트에 연결하여 테스트할 수 있습니다.

동적 분석, 부트로더 조작 또는 하드웨어 보안 테스트를 통해 이미 루트 셸을 얻은 경우, 임플란트나 리버스 셸과 같은 미리 컴파일된 악성 바이너리를 실행할 수 있습니다. Metasploit 프레임워크와 'msfvenom'과 같은 자동화된 페이로드/임플란트 도구를 다음 단계에 따라 활용할 수 있습니다:

1. 대상 펌웨어 아키텍처와 엔디안 형식을 식별해야 합니다.
2. Msfvenom을 사용하여 대상 페이로드, 공격자 호스트 IP, 리스닝 포트 번호, 파일 유형, 아키텍처, 플랫폼 및 출력 파일을 지정할 수 있습니다.
3. 페이로드는 손상된 장치로 전송되고 실행 권한이 있는지 확인해야 합니다.
4. Metasploit은 msfconsole을 시작하고 페이로드에 따라 설정을 구성하여 들어오는 요청을 처리할 준비를 할 수 있습니다.
5. 손상된 장치에서 meterpreter 리버스 셸을 실행할 수 있습니다.
6. meterpreter 세션이 열릴 때 모니터링할 수 있습니다.
7. 포스트 익스플로잇 활동을 수행할 수 있습니다.

가능한 경우, 시작 스크립트 내의 취약점을 악용하여 재부팅 간 장치에 지속적으로 접근할 수 있습니다. 이러한 취약점은 시작 스크립트가 신뢰할 수 없는 마운트 위치(예: SD 카드 및 루트 파일 시스템 외부의 데이터를 저장하는 데 사용되는 플래시 볼륨)에 있는 코드를 참조, [심볼릭 링크](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data) 또는 의존할 때 발생합니다.

## 참고문헌

- 추가 정보는 [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)를 확인하세요.

{{#include ../../banners/hacktricks-training.md}}
