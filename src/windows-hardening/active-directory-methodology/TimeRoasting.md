## TimeRoasting

timeRoasting의 주요 원인은 Microsoft가 NTP 서버에 대한 확장에서 남긴 구식 인증 메커니즘인 MS-SNTP입니다. 이 메커니즘에서 클라이언트는 컴퓨터 계정의 상대 식별자(RID)를 직접 사용할 수 있으며, 도메인 컨트롤러는 컴퓨터 계정의 NTLM 해시(MD4로 생성됨)를 키로 사용하여 응답 패킷의 **메시지 인증 코드(MAC)**를 생성합니다.

공격자는 이 메커니즘을 이용하여 인증 없이 임의의 컴퓨터 계정의 동등한 해시 값을 얻을 수 있습니다. 분명히, 우리는 Hashcat과 같은 도구를 사용하여 무차별 대입 공격을 수행할 수 있습니다.

구체적인 메커니즘은 [MS-SNTP 프로토콜에 대한 공식 Windows 문서](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)의 섹션 3.1.5.1 "인증 요청 동작"에서 확인할 수 있습니다.

문서에서 섹션 3.1.5.1은 인증 요청 동작을 다룹니다.
![](../../images/Pasted%20image%2020250709114508.png)
ExtendedAuthenticatorSupported ADM 요소가 `false`로 설정되면 원래의 Markdown 형식이 유지되는 것을 볼 수 있습니다.

>원문 인용：
>>ExtendedAuthenticatorSupported ADM 요소가 false인 경우, 클라이언트는 클라이언트 NTP 요청 메시지를 구성해야 합니다. 클라이언트 NTP 요청 메시지의 길이는 68바이트입니다. 클라이언트는 섹션 2.2.1에 설명된 대로 클라이언트 NTP 요청 메시지의 인증자 필드를 설정하고, RID 값의 가장 낮은 31비트를 인증자의 키 식별자 하위 필드의 가장 낮은 31비트에 기록한 다음, 키 선택자 값을 키 식별자 하위 필드의 가장 높은 비트에 기록합니다.

문서 섹션 4 프로토콜 예제 3항

>원문 인용：
>>3. 요청을 수신한 후, 서버는 수신된 메시지 크기가 68바이트인지 확인합니다. 그렇지 않은 경우, 서버는 요청을 삭제하거나(메시지 크기가 48바이트와 같지 않은 경우) 인증되지 않은 요청으로 처리합니다(메시지 크기가 48바이트인 경우). 수신된 메시지 크기가 68바이트라고 가정하면, 서버는 수신된 메시지에서 RID를 추출합니다. 서버는 이를 사용하여 NetrLogonComputeServerDigest 메서드를 호출하여( [MS-NRPC] 섹션 3.5.4.8.2에 명시됨) 암호 체크섬을 계산하고, 수신된 메시지의 키 식별자 하위 필드에서 가장 높은 비트를 기준으로 암호 체크섬을 선택합니다(섹션 3.2.5에 명시됨). 그런 다음 서버는 클라이언트에게 응답을 보내며, 키 식별자 필드를 0으로 설정하고 암호 체크섬 필드를 계산된 암호 체크섬으로 설정합니다.

위 Microsoft 공식 문서의 설명에 따르면, 사용자는 인증이 필요하지 않으며, RID를 입력하여 요청을 시작하면 암호 체크섬을 얻을 수 있습니다. 암호 체크섬은 문서의 섹션 3.2.5.1.1에서 설명됩니다.

>원문 인용：
>>서버는 클라이언트 NTP 요청 메시지의 인증자 필드의 키 식별자 하위 필드에서 가장 낮은 31비트에서 RID를 검색합니다. 서버는 NetrLogonComputeServerDigest 메서드를 사용하여( [MS-NRPC] 섹션 3.5.4.8.2에 명시됨) 다음 입력 매개변수로 암호 체크섬을 계산합니다:
>>>![](../../images/Pasted%20image%2020250709115757.png)

암호 체크섬은 MD5를 사용하여 계산되며, 구체적인 과정은 문서의 내용에서 참조할 수 있습니다. 이는 우리가 로스팅 공격을 수행할 기회를 제공합니다.

## how to attack

Quote to https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-timeroasting/

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting scripts by Tom Tervoort
```
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
