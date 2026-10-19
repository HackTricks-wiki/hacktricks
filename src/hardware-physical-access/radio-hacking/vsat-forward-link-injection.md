# VSAT 순방향 링크 신호 주입

{{#include ../../banners/hacktricks-training.md}}

VSAT 단말은 일반적으로 위성 다운링크를 운영자의 허브에서 오는 트래픽으로 취급합니다. DVB-RCS 시스템에서 순방향 링크는 사용자 IP 패킷과 모뎀 제어 메시지를 모두 전달할 수 있습니다. 수신기가 메시지를 처리하기 전에 인증하지 않는다면, 로컬에서 주입한 신호가 무선에서 제어 평면으로 이어지는 신뢰 경계를 넘을 수 있습니다. 이는 **단말에 대한 다운링크 주입**이지, 위성으로의 업링크나 수동적 다운링크 도청이 아닙니다. 실제로 가능한 결과는 DVB-RCS 자체가 아니라 모뎀의 프로토콜 구현과 메시지 인증 여부에 따라 달라집니다.<sup>[[1]](#references)[[2]](#references)</sup>

## RF 격리 실험실에서 테스트하기

소유한 단말과 해당 펌웨어를 사용하고, 적절한 감쇠기를 거쳐 모뎀의 수신 입력에 연결한 SDR 또는 차폐된 RF 환경을 이용하세요. 실제 위성 채널로 송신하지 마세요. 먼저 단말에 설정된 시작 캐리어, 심볼 레이트, population ID를 기록하세요. 이는 순방향 링크 획득에 참고가 됩니다.<sup>[[1]](#references)[[3]](#references)</sup> DVB-RCS 획득 과정에서는 Network Information Table (NIT)을 사용해 RCS Map Table (RMT)을 찾은 다음, Program Association Table (PAT)과 Program Map Table (PMT)을 통해 순방향 링크 시그널링 스트림을 찾습니다. 데이터 스트림에 도달하기 전에 단말이 여러 전송 스트림 캐리어로 재조정할 수 있습니다.<sup>[[3]](#references)</sup>

1. 대상의 시작 전송 스트림을 디코딩하거나 재구성하고 NIT, RMT, 서비스 ID, 패킷 ID (PID), 클록 기준 처리를 살펴보세요. 표준과 대상의 파서 및 로그를 비교하세요. 벤더별 순서나 디스크립터 때문에 올바른 스트림도 수신되지 않을 수 있습니다.
2. 실험실 송신기에서 무해한 UDP 프로브를 `UDP/IP → MPE → MPEG-TS → DVB-S2 I/Q`로 캡슐화한 다음 SDR sink를 통해 격리된 수신 경로로 전달하세요. 전송 스트림의 Program Clock Reference (PCR)를 바이트 레이트에 맞게 유지하세요. 그렇지 않으면 모뎀이 프로브를 처리하기 전에 동기화를 잃을 수 있습니다.
3. 소유한 내부 엔드포인트에서 **복조기 잠금**과 프로브 수신 여부를 모두 확인하세요. 잠금은 물리 계층이 파형을 수신했다는 점만 입증합니다. 그런 다음 이미지 설치나 서비스 설정 변경 없이, 인증되지 않은 관리 또는 업데이트 *시그널링*이 노출되는지 확인하세요.

공개된 MDM2200 사례에서는 GNU Radio 소스 모듈로 DVB-RCS/MPE/MPEG-TS를 생성하고, DVB-S2 변조에는 `gr-dtv`를 사용했습니다. 해당 모뎀에는 대상별 초기화 세부 정보가 필요했습니다. PAT/PMT 앞에 SDT가 있어야 했고, table ID가 `0x3E`인 RCS content descriptor와 GSE/4CPM 모드에 맞는 RMT private byte `0x01`이 필요했습니다. 이 값이 다른 단말에서도 동작한다고 가정하지 마세요.<sup>[[1]](#references)</sup> 연구진은 해당 환경에서 멀티캐스트 MPE 패킷이 수신 모뎀에 도달하는 것도 관찰했습니다. 따라서 대상 지정은 알려진 유니캐스트 MAC 주소에만 한정되지 않았습니다.<sup>[[1]](#references)</sup> 별도의 분석에서는 연구 대상 시스템에서 보호되지 않은 제어 및 소프트웨어 업데이트 시그널링을 확인했지만, 이 결과는 구현별로 검증해야 합니다.<sup>[[2]](#references)</sup>

사용자 트래픽에 IPsec 또는 VPN 터널을 사용하더라도 그 이전 단계의 DVB-RCS 시그널링이나 모뎀 자체의 업데이트 파서는 인증되지 않습니다. 승인된 평가에서는 보안 사용자 터널이 무선 주입을 차단한다는 증거로 간주하지 말고 **사용자 IP**, **순방향 링크 제어**, **유지보수/복구** 트래픽의 암호화 보호를 각각 구분하세요.<sup>[[1]](#references)[[2]](#references)</sup>

초기 I/Q 검사는 [무선 신호 분석](../hardware-hacking/radio.md)을 참고하세요. 보드에서 펌웨어와 파서를 살펴보려면 [펌웨어 분석](../firmware-analysis/)을 참고하세요. 다른 인터페이스는 [Radio Hacking 개요](./)에서 확인하세요.

## References

- [1] [Bisping et al. - VSAT 위성 모뎀에 대한 무선 신호 주입 공격 (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bisping.pdf)
- [2] [Willbold et al. - VSAsTer: 현재 VSAT 시스템 운영의 내재적 보안 문제 발견 (WiSec 2024)](https://www.lenders.ch/publications/conferences/wisec24.pdf)
- [3] [ETSI EN 301 790 - 위성 배포 시스템을 위한 DVB 상호작용 채널](https://www.etsi.org/deliver/etsi_en/301700_301799/301790/01.04.01_40/en_301790v010401o.pdf)
{{#include ../../banners/hacktricks-training.md}}
