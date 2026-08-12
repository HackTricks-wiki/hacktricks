# 산업 제어 시스템 Hacking

{{#include ../../banners/hacktricks-training.md}}

## 이 섹션에 관하여

이 섹션에서는 산업 제어 시스템(ICS)의 구성 요소, 아키텍처, 프로토콜 및 보안 평가 방법을 소개합니다. ICS는 물리적 프로세스를 모니터링하거나 변경을 일으키는 프로그래밍 가능한 시스템과 장치를 포함하는 더 광범위한 운영 기술(OT) 영역의 일부입니다. 일반적인 예로는 supervisory control and data acquisition (SCADA) 시스템, distributed control systems (DCSs), programmable logic controllers (PLCs)가 있습니다.<sup>[[1]](#references)</sup>

이러한 환경에서의 보안 작업은 기존 IT와 다른 요구 사항을 고려해야 합니다. 여기에는 프로세스 안전, 신뢰성, 가용성, 결정론적 운영 및 장비 수명 주기가 포함됩니다. 기술적으로 유효한 보안 제어라도 물리적 프로세스를 방해한다면 적합하지 않을 수 있으므로, 테스트와 remediation은 시스템 소유자 및 운영 담당자와 조율해야 합니다.<sup>[[1]](#references)</sup>

침해 또는 우발적인 운영 중단은 생산 중단, 장비 손상, 위험 물질 방출, 환경 피해, 부상 및 인명 손실을 초래할 수 있습니다. 이러한 잠재적 물리적 영향 때문에 active testing에 앞서 제어 대상 프로세스와 안전한 운영 한계를 이해해야 합니다.<sup>[[1]](#references)</sup>

많은 OT 배포 환경에서는 장비의 긴 서비스 수명과 변경에 필요한 운영 및 안전 테스트 때문에 레거시 운영 체제, 애플리케이션 및 프로토콜을 계속 사용합니다. 일부 프로토콜은 최신 authentication 또는 encryption 없이 설계되었으며, vendor 지원 또는 maintenance window로 인해 patching이 제한될 수 있습니다. 직접적인 업그레이드가 현실적으로 불가능한 경우에는 segmentation, access control 및 monitoring으로 보완해야 합니다.<sup>[[1]](#references)</sup>

## 평가 우선순위

제어 대상 프로세스, 시스템 경계, 네트워크 토폴로지, 자산, 데이터 흐름, trust relationship 및 외부 연결을 이해하는 것부터 시작합니다. 유사한 장치 유형이라도 사이트마다 서로 다른 기능을 수행할 수 있으므로, 한 배포 환경의 아키텍처나 영향 모델이 다른 환경에도 적용된다고 가정하지 않아야 합니다.<sup>[[1]](#references)</sup>

가능한 경우 passive discovery와 기존 engineering 문서를 우선 사용합니다. 모든 active scanning 또는 exploitation은 안전 제약 조건, maintenance window, 복구 절차 및 중지 조건을 정의한 승인된 test plan에 따라 수행해야 합니다. Findings는 cybersecurity 영향과 물리적 프로세스에 대한 잠재적 영향을 모두 고려하여 평가해야 합니다.<sup>[[1]](#references)</sup>

동일한 아키텍처 지식은 자산 inventory, network segmentation, monitoring, incident response 및 risk-based vulnerability management와 같은 방어 활동에도 활용됩니다.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - 운영 기술(OT) 보안 가이드](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
