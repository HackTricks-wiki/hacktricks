# Modbus 프로토콜

{{#include ../../banners/hacktricks-training.md}}

## Modbus 소개

Modbus는 PLC, 센서, 액추에이터 및 기타 산업용 장치에서 널리 구현되는 개방형 애플리케이션 계층 프로토콜입니다. 요청/응답 모델은 function code를 통해 coil과 register를 노출합니다. 따라서 Security testing은 단순히 TCP port 502를 찾는 것이 아니라, 무단 읽기/쓰기, traffic observation, replay 및 안전하지 않은 장치 동작에 초점을 맞춥니다.<sup>[[1]](#references)</sup>

많은 배포 환경에서는 업그레이드에 가동 중지, 재인증 또는 field device 교체가 필요하기 때문에 legacy serial 장비를 계속 사용합니다. 기존 Modbus는 confidentiality와 peer authentication을 모두 제공하지 않습니다. Modbus Security는 X.509 certificate와 TCP port 802를 사용하는 별도의 TLS 기반 profile입니다. 또한 specification이 공개되어 있고 독립적으로 구현할 수 있으므로 vendor 동작과 optional-function 지원은 서로 다를 수 있으며, 이를 가정하지 말고 fingerprinting해야 합니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Client-Server 아키텍처

현재 용어에서 **client**는 transaction을 시작하고 **server**는 response를 반환합니다. 이전 문서에서는 **master/slave**라는 용어를 사용합니다. 이 애플리케이션 관계를 SPI 또는 I2C와 혼동하지 마십시오. 이들은 서로 다른 bus protocol입니다.<sup>[[1]](#references)</sup>

## Serial 및 Ethernet transport

동일한 Modbus 애플리케이션 data는 serial variant(RTU 또는 ASCII framing)와 Modbus TCP를 통해 전송할 수 있습니다. Modbus TCP는 MBAP header를 추가하며 일반적으로 TCP port 502를 사용합니다. serial RTU는 compact binary framing과 CRC를 사용하고, serial ASCII는 byte를 hexadecimal character로 표현하며 LRC를 사용합니다.<sup>[[1]](#references)[[3]](#references)</sup>

## Data 표현

data model은 single-bit coil/discrete input과 16-bit input/holding register로 구성됩니다. multi-register value, byte order, scaling 및 semantic meaning은 device-specific하며 vendor의 register map을 기준으로 확인해야 합니다.<sup>[[1]](#references)</sup>

## Function code

Function code는 coil 읽기(`0x01`), holding register 읽기(`0x03`), 단일 coil/register 쓰기(`0x05`/`0x06`), 여러 coil/register 쓰기(`0x0F`/`0x10`)와 같은 operation을 선택합니다. 캡처된 write request는 해당 deployment에 보완적인 authentication 또는 process-state check가 없을 경우 replay할 수 있습니다. 장거리 serial 배선에 대한 authorized physical access가 있는 경우, assessor는 electrical interface, termination 및 안전한 connection method를 식별한 후 배선에서 직접 frame을 캡처하거나 inject할 수도 있습니다. 두 작업 모두 physical process에 영향을 줄 수 있으므로 lab 환경 또는 명시적인 operational authorization을 사용하십시오.<sup>[[1]](#references)[[3]](#references)</sup>

## Addressing

Serial device는 unit address를 사용합니다. Modbus TCP는 IP addressing과 MBAP header의 Unit Identifier를 함께 사용하며, 이는 TCP-to-serial gateway가 downstream unit으로 request를 route할 때 특히 중요합니다. 제품 문서에 표시된 register reference는 one-based(`40001`)일 수 있지만 protocol address는 zero-based이므로, 이는 off-by-one error의 일반적인 원인입니다.<sup>[[1]](#references)[[3]](#references)</sup>

Serial framing에는 transmission-error check가 포함됩니다(RTU의 CRC 및 ASCII의 LRC). TCP는 일반적인 transport checksum을 제공합니다. 이러한 기능은 우발적인 corruption을 감지할 뿐 cryptographic integrity나 origin authentication을 제공하지 않습니다.<sup>[[3]](#references)</sup>

Authorized assessment 중에는 exposure, 허용된 function code, writable address range, exception handling, rate limit, 그리고 network segmentation 또는 Modbus-aware firewall이 client를 제한하는지 여부를 test하십시오. 관련 threat에는 passive disclosure, unauthorized command injection, replay, data forgery 및 denial of service가 포함됩니다. 겉보기에 작은 register 변경도 physical process를 변경할 수 있으므로 모든 active test를 process owner와 조율하십시오.

## References

- [1] [Modbus Organization — Modbus 애플리케이션 프로토콜 사양 V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Modbus Organization — Modbus Security 프로토콜 및 구현 가이드](https://www.modbus.org/modbus-specifications)
- [3] [Modbus Organization — Serial Line을 통한 Modbus 사양 및 구현 가이드 V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
