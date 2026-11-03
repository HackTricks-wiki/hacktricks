# 산업 제어 시스템 해킹

{{#include ../banners/hacktricks-training.md}}

## 이 섹션 소개

이 섹션에서는 산업 제어 시스템(ICS)의 구성 요소, 아키텍처, 프로토콜 및 보안 평가 방법을 소개합니다. ICS는 물리적 프로세스를 모니터링하거나 변경하는 프로그래밍 가능한 시스템과 장치로 이루어진 더 광범위한 운영 기술(OT) 영역에 속합니다. 일반적인 예로는 감시 제어 및 데이터 수집(SCADA) 시스템, 분산 제어 시스템(DCS), 프로그래머블 로직 컨트롤러(PLC)가 있습니다.<sup>[[1]](#references)</sup>

이러한 환경에서 보안 작업을 수행할 때는 공정 안전, 신뢰성, 가용성, 결정론적 운영, 장비 수명 주기 등 기존 IT와는 다른 요구 사항을 고려해야 합니다. 기술적으로 유효한 보안 제어라도 물리적 프로세스를 방해한다면 적합하지 않을 수 있으므로, 테스트와 개선 작업은 시스템 소유자 및 운영 담당자와 협의해야 합니다.<sup>[[1]](#references)</sup>

시스템 침해나 우발적인 장애는 생산 중단, 장비 손상, 유해 물질 유출, 환경 피해, 부상 또는 인명 손실로 이어질 수 있습니다. 이러한 잠재적인 물리적 영향 때문에 능동적인 테스트에 앞서 제어 대상 프로세스와 안전 운전 한계를 파악해야 합니다.<sup>[[1]](#references)</sup>

장비 수명이 길고 변경 사항에 운영 및 안전 테스트가 필요하기 때문에 많은 OT 환경에서는 오래된 운영 체제, 애플리케이션, 프로토콜을 계속 사용합니다. 일부 프로토콜은 최신 인증이나 암호화 기능 없이 설계되었으며, 공급업체 지원이나 유지보수 기간의 제약으로 패치 적용이 어려울 수 있습니다. 직접 업그레이드가 불가능한 경우에는 네트워크 분할, 접근 제어, 모니터링으로 보완하세요.<sup>[[1]](#references)</sup>

## 평가 우선순위

먼저 제어 대상 프로세스, 시스템 경계, 네트워크 토폴로지, 자산, 데이터 흐름, 신뢰 관계, 외부 연결을 파악하세요. 같은 유형의 장치라도 사이트마다 역할이 다를 수 있으므로, 한 환경의 아키텍처나 영향 모델이 다른 환경에도 적용된다고 가정하지 마세요.<sup>[[1]](#references)</sup>

가능하면 수동 검색과 기존 엔지니어링 문서를 우선 활용하세요. 능동 스캔이나 익스플로잇은 안전 제약, 유지보수 기간, 복구 절차, 중단 조건을 명시한 승인된 테스트 계획에 따라야 합니다. 발견 사항은 사이버 보안 영향과 물리적 프로세스에 미칠 수 있는 영향을 모두 고려해 평가해야 합니다.<sup>[[1]](#references)</sup>

동일한 아키텍처 지식은 자산 인벤토리, 네트워크 분할, 모니터링, 사고 대응, 위험 기반 취약점 관리 등의 방어 활동에도 도움이 됩니다.<sup>[[1]](#references)</sup>

## 감독용 냉동 컨트롤러 악용

냉동 시스템 관리자는 압축기 및 케이스 컨트롤러를 조정하지만, 직접 케이스를 냉각하지는 않습니다. 따라서 관리 인터페이스에 접근할 수 있으면 일반적인 구성 배포를 통해 여러 하위 장치를 제어할 수 있습니다. 이는 온도 조절 장치 하나의 설정을 변경하거나 압축기를 직접 구동하는 것과는 다릅니다.<sup>[[3]](#references)[[4]](#references)</sup>

### 날짜 기반 유지보수 코드 로그인

영향을 받는 Danfoss 시스템 관리자에서는 대체 XML 로그인 기능이 계정 암호 대신 컨트롤러 날짜에서 파생된 코드를 허용합니다.<sup>[[2]](#references)[[3]](#references)</sup> SM800 및 SC255에서 Synacktiv는 `eds_only` 및 `quantum_only` 속성이 `xml_load_file`과 `check_authorize`를 거쳐 `check_code_of_day`에 도달하는 경로를 추적했습니다. 또한 이 권고문에서는 `xml.cgi`의 `read_date_time`을 통해 인증 없이 컨트롤러 날짜를 알아낼 수 있음을 보여 줍니다.<sup>[[2]](#references)</sup> Claroty는 AK-SM 800A에서 이에 상응하는 `getauth` 경로를 발견했지만, 트리거 속성은 공개하지 않았습니다. 따라서 구형 모델의 속성 이름이 해당 플랫폼에서도 작동한다고 가정해서는 안 됩니다.<sup>[[3]](#references)</sup>

Synacktiv는 인증 없이 날짜를 조회하는 방법을 다음과 같이 설명합니다.<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

코드에는 장치별 비밀값이 없습니다. [firmware](../hardware-physical-access/firmware-analysis/)에서 알고리즘을 복구하면 같은 취약 구현을 사용하는 장치에서 유효한 날짜 기반 자격 증명을 얻을 수 있습니다.<sup>[[2]](#references)[[3]](#references)</sup> 먼저 모델과 firmware를 확인하세요. 날짜에 따른 응답만으로는 대체 로그인이 존재하거나 세션을 획득했다는 사실이 입증되지 않습니다.

### 일괄 구성 및 제상 히터 악용

관리자 권한을 얻은 후에는 시스템 매니저에 매핑된 쇼케이스 컨트롤러와 구성 배포 기능으로 컨트롤러를 한꺼번에 업데이트할 수 있는지 확인하세요. 쇼케이스 setpoint를 변경하면 보통 캐비닛 온도가 실내 온도에 가까워질 뿐입니다. 주변 온도보다 더 높이 가열하려면 쇼케이스 컨트롤러의 전기식 증발기 제상 히터를 제어해야 합니다. 제상 중에는 냉각이 중단되고, 센서나 타이머가 주기를 종료할 때까지 히터가 작동합니다. 대신 제상 방식, 일정, 종료 온도, 시간 제한을 변경하면 히터를 계속 작동시킬 수 있습니다. 매니저는 이러한 변경 사항을 여러 쇼케이스에 배포하고 관련 경보를 억제할 수 있으므로, 감독 시스템 하나가 침해되면 매장 전체의 프로세스가 바뀔 수 있습니다.<sup>[[4]](#references)</sup>

이는 물리적 프로세스에 대한 위험이며, 운영 중인 시스템에서 안전하게 수행할 수 있는 개념 증명이 아닙니다. 열 차단 장치가 있으면 히터 작동을 제한할 수 있지만, 계속 작동하면 이미 약해진 전기 연결부가 과열될 수 있습니다. 구성과 영향을 검증하려면 승인된 실험실에서 수행하거나 운영자의 프로세스 안전 계획을 따르세요.<sup>[[4]](#references)</sup>

## 프로토콜 진입점

- [Modbus 테스트](../network-services-pentesting/pentesting-modbus.md)에서는 Modbus TCP, 직렬 방식 변형, 기능 코드, 레지스터 접근을 다룹니다.
- [OPC UA 테스트](../network-services-pentesting/4840-pentesting-opc-ua.md)에서는 산업용 데이터 교환 서비스를 다룹니다.
- [BACnet 테스트](../network-services-pentesting/47808-udp-bacnet.md)에서는 빌딩 자동화 제어 네트워크를 다룹니다.

## References

- [1] [NIST SP 800-82 Rev. 3 - 운영 기술(OT) 보안 가이드](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv - Danfoss System-Managers SM800 및 SC255의 인증 우회](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 - 컨트롤러를 얼리고 식품을 해동하다](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners - 냉장고를 데우는 데 국가 단위 공격자는 필요 없다](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)
{{#include ../banners/hacktricks-training.md}}
