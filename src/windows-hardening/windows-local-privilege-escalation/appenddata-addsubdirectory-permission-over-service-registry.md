{{#include ../../banners/hacktricks-training.md}}

**원본 게시물은** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## 요약

현재 사용자에 의해 쓰기 가능한 두 개의 레지스트리 키가 발견되었습니다:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

**RpcEptMapper** 서비스의 권한을 **regedit GUI**를 사용하여 확인할 것을 제안했습니다. 특히 **고급 보안 설정** 창의 **유효한 권한** 탭을 통해 특정 사용자 또는 그룹에 부여된 권한을 개별적으로 각 접근 제어 항목(ACE)을 검토할 필요 없이 평가할 수 있습니다.

스크린샷은 낮은 권한의 사용자에게 할당된 권한을 보여주었으며, 그 중 **하위 키 생성** 권한이 주목할 만했습니다. 이 권한은 **AppendData/AddSubdirectory**라고도 하며, 스크립트의 발견과 일치합니다.

특정 값을 직접 수정할 수는 없지만, 새로운 하위 키를 생성할 수 있는 능력이 주목되었습니다. 예를 들어, **ImagePath** 값을 변경하려는 시도가 있었으나 접근 거부 메시지가 나타났습니다.

이러한 제한에도 불구하고, **RpcEptMapper** 서비스의 레지스트리 구조 내에서 기본적으로 존재하지 않는 **Performance** 하위 키를 활용할 가능성을 통해 권한 상승의 잠재력이 확인되었습니다. 이는 DLL 등록 및 성능 모니터링을 가능하게 할 수 있습니다.

**Performance** 하위 키와 성능 모니터링을 위한 활용에 대한 문서가 참고되었고, 이를 바탕으로 개념 증명 DLL이 개발되었습니다. 이 DLL은 **OpenPerfData**, **CollectPerfData**, **ClosePerfData** 함수를 구현하는 것을 보여주었으며, **rundll32**를 통해 테스트하여 성공적으로 작동함을 확인했습니다.

목표는 조작된 Performance DLL을 로드하도록 **RPC Endpoint Mapper 서비스**를 강제하는 것이었습니다. 관찰 결과, PowerShell을 통해 성능 데이터와 관련된 WMI 클래스 쿼리를 실행하면 로그 파일이 생성되어 **LOCAL SYSTEM** 컨텍스트에서 임의 코드를 실행할 수 있게 되어 권한이 상승했습니다.

이 취약점의 지속성과 잠재적 영향이 강조되었으며, 이는 후속 공격 전략, 측면 이동 및 안티바이러스/EDR 시스템 회피와 관련이 있음을 나타냅니다.

이 취약점은 처음에 스크립트를 통해 의도치 않게 공개되었지만, 그 이용은 구식 Windows 버전(예: **Windows 7 / Server 2008 R2**)에 제한되며 로컬 접근이 필요하다는 점이 강조되었습니다.

{{#include ../../banners/hacktricks-training.md}}
