# macOS Serial Number

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

2010년 이후 출시된 Apple 기기의 serial number는 **12개의 영숫자 문자**로 구성되며, 각 segment는 특정 정보를 나타냅니다:

- **처음 3개 문자**: **manufacturing location**을 나타냅니다.
- **4번째 및 5번째 문자**: **manufacture year와 week**를 나타냅니다.
- **6~8번째 문자**: 각 기기의 **unique identifier** 역할을 합니다.
- **마지막 4개 문자**: **model number**를 지정합니다.

예를 들어 **C02L13ECF8J2** serial number는 이 구조를 따릅니다.

### **Manufacturing Locations (처음 3개 문자)**

일부 code는 특정 factory를 나타냅니다:

- **FC, F, XA/XB/QP/G8**: 미국 내 여러 location.
- **RN**: 멕시코.
- **CK**: Cork, Ireland.
- **VM**: Foxconn, Czech Republic.
- **SG/E**: 싱가포르.
- **MB**: 말레이시아.
- **PT/CY**: 한국.
- **EE/QT/UV**: 대만.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: 중국 내 여러 location.
- **C0, C3, C7**: 중국의 특정 city.
- **RM**: Refurbished devices.

### **Year of Manufacturing (4번째 문자)**

이 문자는 'C'(2010년 상반기를 의미)부터 'Z'(2019년 하반기)까지 다양하며, 각 문자는 서로 다른 반년 기간을 나타냅니다.

### **Week of Manufacturing (5번째 문자)**

숫자 1-9는 1~9주차에 해당합니다. 모음과 'S'를 제외한 C-Y 문자는 10~27주차를 나타냅니다. 연도 하반기의 경우 이 숫자에 26을 더합니다.

{{#include ../../../banners/hacktricks-training.md}}
