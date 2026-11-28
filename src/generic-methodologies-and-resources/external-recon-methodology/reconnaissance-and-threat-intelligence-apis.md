# 정찰 및 위협 인텔리전스 API

{{#include ../../banners/hacktricks-training.md}}

이 서비스들은 정찰, 평판 확인, 침해 여부 확인 또는 데이터 보강 작업을 지원합니다. API, 할당량, 가격, 허용되는 사용 방식은 자주 바뀌므로 고객 식별자나 민감한 데이터를 전송하기 전에 최신 벤더 문서와 계약상 권한을 확인하세요. 자산 검색 순서는 [External Recon Methodology](README.md)를 참조하세요.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

IP 주소가 의심스럽거나 악의적인 활동과 연관된 적이 있는지 조회합니다. 이용하려면 계정이나 API key가 필요할 수 있습니다.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

IP 주소, 사용자 이름 또는 이메일 주소가 자동 계정 등록이나 신고된 기타 bot 활동과 연관된 적이 있는지 확인합니다.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

업무용 이메일 주소와 도메인 관련 연락처 패턴을 찾고 검증합니다. 요청 한도와 허용되는 사용 방식은 현재 요금제를 확인하세요.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

IP 주소 및 도메인과 관련된 위협 인텔리전스 지표와 활동을 검색합니다.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

사용 가능한 비즈니스/프로필 데이터로 이메일 주소, 도메인 또는 회사 정보를 보강합니다. 데이터 범위, 접근 권한, 개인정보 보호 제약은 현재 제품과 요금제에 따라 다릅니다.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

웹사이트에서 관찰된 기술을 식별하고, 선택한 요금제에서 허용하는 경우 과거 데이터나 관계 데이터를 확인합니다.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

IP 주소가 의심스럽거나 악의적인 활동과 연관되어 있는지 확인합니다. 현재 API 요금제와 한도를 확인하세요.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

도메인, URL 또는 IP 주소의 FortiGuard 분류 및 위협 인텔리전스를 조회합니다. 사용 가능 여부는 서비스마다 다릅니다.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

IP 주소가 스팸 활동 신고로 등록되어 있는지 확인합니다.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

서비스의 커뮤니티 및 기타 신호를 바탕으로 한 도메인 평판을 조회합니다.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

IP 주소의 지리적 위치, ASN, 조직 및 관련 메타데이터를 확인합니다. 할당량은 현재 요금제를 확인하세요.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

이 플랫폼은 과거 DNS 해석 결과, IP 또는 name server와 연관된 도메인, 관련 레코드 등 DNS 및 인프라 인텔리전스를 제공합니다. 과거 DNS를 통해 이전 origin 주소를 알아낼 수 있지만, CDN을 안정적으로 우회할 수 있는 방법은 아니므로 검증이 필요합니다.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

사용 가능한 신원 및 비즈니스 속성으로 이메일 주소, 도메인 또는 회사 이름의 정보를 보강합니다. 개인정보는 권한 및 개인정보 보호 요건에 따라 처리하세요.

## RiskIQ / Microsoft Defender Threat Intelligence (기존 서비스 전환) <sup>[[14]](#references)</sup>

RiskIQ의 PassiveTotal 기능은 Microsoft Defender Threat Intelligence로 전환되었습니다. 제품 접근 권한, API 및 유지된 기능이 변경되었으므로 기존 PassiveTotal 관련 가정에 의존하지 말고 Microsoft의 최신 문서를 확인하세요.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

서비스의 접근 제어를 준수하며 도메인, IP 주소, 이메일 주소 및 색인된 과거 데이터나 leak 데이터를 검색합니다.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

IP 주소 및 기타 지표의 위협 인텔리전스와 평판 데이터를 검색합니다.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

IP 주소 또는 범위에서 관찰된 인터넷 스캔 및 일반적인 서비스 활동을 검색합니다. 현재 체험판 및 커뮤니티 접근 조건을 확인하세요.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

IP 주소, 호스트 또는 검색 쿼리에 대한 인터넷 스캔 및 서비스 정보를 조회합니다. API 접근은 계정 요금제에 따라 다릅니다.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

호스트, 인증서, 도메인 및 인터넷 서비스 데이터셋을 검색합니다. 데이터 모델과 범위는 Shodan과 다릅니다.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

키워드로 공개적으로 관찰된 클라우드 스토리지 객체 및 bucket의 제공업체 색인을 검색합니다.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

색인된 침해 데이터에서 이메일 주소, 사용자 이름, 도메인 및 관련 레코드를 검색합니다. 권한이 있는 경우에만 사용하고 침해 데이터가 불필요하게 노출되지 않도록 하세요.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

색인된 paste 콘텐츠에서 이메일 주소나 다른 용어가 등장하는지 검색합니다. 연동하기 전에 서비스가 여전히 제공되는지 확인하세요.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

이메일 주소의 평판 및 위험 신호를 조회합니다.

## GhostProject (과거 서비스) <sup>[[24]](#references)</sup>

과거에는 leak된 이메일/비밀번호 데이터를 검색할 수 있다고 홍보했습니다. 이 서비스는 위험성이 높은 제3자 데이터 처리 서비스로 간주하고, 사용 전에 이용 가능 여부, 적법성 및 권한을 확인하세요.

## BinaryEdge (서비스 중단) <sup>[[25]](#references)</sup>

IP 주소 및 관련 자산에 대한 인터넷 스캔, 노출 및 위협 인텔리전스 데이터를 제공했습니다. 현재 사이트는 Coalition 전환 안내로 리디렉션되며 API 요청이 거부되므로, 이용할 수 없는 서비스로 간주하세요.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

이메일 주소 또는 검증된 도메인이 알려진 침해 사고에 포함되어 있는지 확인합니다. 별도 서비스인 Pwned Passwords는 prefix를 사용해 비밀번호 hash를 확인하며, 평문 비밀번호를 **노출하지 않습니다**.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

IP 지리적 위치, 데이터 센터, ASN, proxy/VPN 및 관련 보강 정보를 조회합니다. 할당량은 현재 요금제에 따라 다릅니다.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
선택한 데이터 포인트를 사용해 IP 지리적 위치 및 OSINT 중심의 정보를 보강합니다. 상업적 이용에 관한 최신 약관을 확인하세요.

### [NetAPI](https://netapi.com/) <sup>[[32]](#references)</sup>
도메인(등록 기관, 등록 및 만료 날짜, name server, 호스팅 IP 및 국가)이나 IP 주소(해당 IP에서 호스팅되는 다른 도메인)를 조회하고, 도메인 또는 IP가 무료 침해 목록에 포함되어 있는지 확인합니다. 이 목록에는 phishing 및 sinkhole 처리된 malware 도메인과 지난 48시간 동안 honeypot 센서를 공격한 주소가 포함됩니다. 웹 조회와 침해 확인 API에는 계정이 필요하지 않지만, 조회 API를 이용하려면 유료 요금제가 필요합니다.


[DNSDumpster](https://dnsdumpster.com/)는 DNS 정찰 결과를 제공합니다.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/)는 사이트, 호스팅 및 인터넷 인프라 인텔리전스를 제공합니다.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)는 온라인 subdomain 검색 인터페이스를 제공합니다.<sup>[[31]](#references)</sup>

## References

- [1] [Project Honey Pot](https://www.projecthoneypot.org/)
- [2] [BotScout API](https://botscout.com/api.htm)
- [3] [Hunter API](https://hunter.io/api-documentation)
- [4] [AlienVault OTX API](https://otx.alienvault.com/api)
- [5] [Clearbit](https://dashboard.clearbit.com/)
- [6] [BuiltWith](https://builtwith.com/)
- [7] [FraudGuard](https://fraudguard.io/)
- [8] [FortiGuard Labs](https://www.fortiguard.com/)
- [9] [SpamCop](https://www.spamcop.net/)
- [10] [Web of Trust](https://www.mywot.com/)
- [11] [IPinfo](https://ipinfo.io/)
- [12] [SecurityTrails](https://securitytrails.com/)
- [13] [FullContact](https://www.fullcontact.com/)
- [14] [Microsoft Defender Threat Intelligence](https://learn.microsoft.com/en-us/defender/threat-intelligence/what-is-microsoft-defender-threat-intelligence-defender-ti)
- [15] [Intelligence X](https://intelx.io/)
- [16] [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
- [17] [GreyNoise](https://www.greynoise.io/)
- [18] [Shodan](https://www.shodan.io/)
- [19] [Censys](https://censys.com/)
- [20] [GrayHatWarfare](https://buckets.grayhatwarfare.com/)
- [21] [DeHashed](https://www.dehashed.com/)
- [22] [psbdmp](https://psbdmp.ws/)
- [23] [EmailRep](https://emailrep.io/)
- [24] [Cornell 연구 — 침해된 자격 증명 확인 프로토콜 (GhostProject 포함)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
- [32] [NetAPI API 문서](https://netapi.com/help/api/)
{{#include ../../banners/hacktricks-training.md}}
