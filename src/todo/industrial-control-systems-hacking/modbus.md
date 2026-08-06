# Modbus Protocol

{{#include ../../banners/hacktricks-training.md}}

## Modbus Protocol 소개

Modbus protocol은 Industrial Automation and Control Systems에서 널리 사용되는 protocol입니다. Modbus를 사용하면 programmable logic controllers(PLCs), sensors, actuators 및 기타 industrial devices와 같은 다양한 장치 간에 통신할 수 있습니다. Modbus Protocol을 이해하는 것은 매우 중요합니다. ICS에서 가장 많이 사용되는 communication protocol이며, sniffing은 물론 PLC에 commands를 주입하는 데에도 많은 attack surface를 제공하기 때문입니다.

여기서는 protocol의 개념과 작동 특성을 설명하기 위해 내용을 요점별로 정리합니다. ICS system security에서 가장 큰 과제는 구현 및 업그레이드 비용입니다. 이러한 protocol과 standards는 1980년대와 1990년대 초에 설계되었지만 현재도 널리 사용되고 있습니다. 산업 현장에는 많은 장치와 연결이 존재하므로 장치를 업그레이드하기가 매우 어렵습니다. 이로 인해 hackers는 오래된 protocol을 대상으로 공격할 수 있는 이점을 얻습니다. Modbus에 대한 attacks는 산업 운영에 중요한 protocol이 업그레이드 없이 계속 사용될 것이므로 사실상 피하기 어렵습니다.

## Client-Server Architecture

Modbus Protocol은 일반적으로 Client Server Architecture에서 사용되며, master device(client)가 하나 이상의 slave devices(servers)와 통신을 시작합니다. 이는 Master-Slave architecture라고도 하며, SPI, I2C 등 electronics 및 IoT에서 널리 사용됩니다.

## Serial 및 Etherent Versions

Modbus Protocol은 Serial Communication과 Ethernet Communications 모두를 지원하도록 설계되었습니다. Serial Communication은 legacy systems에서 널리 사용되는 반면, modern devices는 높은 data rates를 제공하고 modern industrial networks에 더 적합한 Ethernet을 지원합니다.

## Data Representation

Data는 Modbus protocol에서 ASCII 또는 Binary 형식으로 전송되지만, 오래된 devices와의 호환성 및 compact한 특성 때문에 binary format이 사용됩니다.

## Function Codes

ModBus Protocol은 PLCs와 다양한 control devices를 작동시키는 데 사용되는 특정 function codes를 전송하는 방식으로 동작합니다. replay attacks는 function codes를 재전송하여 수행할 수 있으므로 이 부분을 이해하는 것이 중요합니다. Legacy devices는 data transmission에 대한 encryption을 지원하지 않으며, 일반적으로 이를 연결하는 긴 wires가 사용됩니다. 이로 인해 wires를 tampering하고 data를 capture하거나 inject할 수 있습니다.

## Modbus Addressing

Network의 각 device에는 devices 간 통신에 필수적인 고유 address가 있습니다. Modbus RTU, Modbus TCP 등의 protocols는 addressing을 구현하는 데 사용되며 data transmission에서 transport layer와 같은 역할을 합니다. 전송되는 data는 message를 포함하는 Modbus protocol format으로 구성됩니다.

또한 Modbus는 전송된 data의 integrity를 보장하기 위해 error checks를 구현합니다. 하지만 무엇보다도 Modbus는 Open Standard이므로 누구나 자신의 devices에 이를 구현할 수 있습니다. 이로 인해 Modbus protocol은 global standard가 되었으며 industrial automation industry 전반에 널리 확산되었습니다.

광범위한 사용과 업그레이드 부족으로 인해 Modbus를 attacking하면 attack surface 측면에서 상당한 이점을 얻을 수 있습니다. ICS는 devices 간 통신에 크게 의존하며, 이러한 devices에 대한 attacks는 industrial systems의 운영에 위험할 수 있습니다. Attacker가 transmission medium을 식별할 수 있다면 replay, data injection, data sniffing 및 leaking, Denial of Service, data forgery 등의 attacks를 수행할 수 있습니다.

{{#include ../../banners/hacktricks-training.md}}
