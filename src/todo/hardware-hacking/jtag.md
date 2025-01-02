# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)은 Raspberry PI 또는 Arduino와 함께 사용하여 알 수 없는 칩의 JTAG 핀을 찾는 도구입니다.\
**Arduino**에서는 **2번에서 11번 핀을 JTAG에 속할 가능성이 있는 10개의 핀에 연결**합니다. Arduino에 프로그램을 로드하면 모든 핀을 브루트포스하여 JTAG에 속하는 핀과 각 핀의 종류를 찾습니다.\
**Raspberry PI**에서는 **1번에서 6번 핀**만 사용할 수 있습니다(6핀, 따라서 각 잠재적 JTAG 핀을 테스트하는 데 더 느리게 진행됩니다).

### Arduino

Arduino에서 케이블을 연결한 후(핀 2에서 11을 JTAG 핀에, Arduino GND를 기본 보드 GND에 연결), **Arduino에 JTAGenum 프로그램을 로드**하고 Serial Monitor에서 **`h`**(도움 요청 명령)를 보내면 도움말을 볼 수 있습니다:

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

**"No line ending" 및 115200baud**로 설정합니다.\
스캔을 시작하려면 s 명령을 보냅니다:

![](<../../images/image (774).png>)

JTAG에 연결되어 있다면 **FOUND!**로 시작하는 하나 이상의 **라인을 찾을 수 있습니다**. 이는 JTAG의 핀을 나타냅니다.

{{#include ../../banners/hacktricks-training.md}}
