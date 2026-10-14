# 정찰 및 위협 인텔리전스 API

{{#include ../../banners/hacktricks-training.md}}

이 서비스들은 정찰, 평판 조회, 침해 데이터 검색 또는 정보 보강 워크플로를 지원합니다. API, 할당량, 가격, 허용된 사용 범위는 자주 바뀌므로 고객 식별자나 민감한 데이터를 전송하기 전에 최신 공급업체 문서와 계약상 허가를 확인하세요. 자산 검색 순서는 [External Recon Methodology](README.md)를 참조하세요.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

IP 주소가 의심스럽거나 악의적인 활동과 연관된 적이 있는지 조회합니다. 계정이나 API 키가 필요할 수 있습니다.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

IP 주소, 사용자 이름 또는 이메일 주소가 자동 계정 등록이나 기타 신고된 bot 활동과 연관된 적이 있는지 확인합니다.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

업무용 이메일 주소와 도메인 관련 연락처 패턴을 찾고 검증합니다. 요청 한도와 허용된 사용 범위는 현재 플랜에서 확인하세요.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

IP 주소 및 도메인과 연관된 위협 인텔리전스 지표와 활동을 검색합니다.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

이메일 주소, 도메인 또는 회사에 사용 가능한 비즈니스/프로필 데이터를 보강합니다. 데이터 범위, 접근 권한 및 개인정보 보호 관련 제약은 현재 제품과 플랜에 따라 다릅니다.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

웹사이트에서 관찰된 기술을 식별하고, 선택한 플랜에서 허용하는 경우 기록 또는 관계 데이터를 확인합니다.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

IP 주소가 의심스럽거나 악의적인 활동과 연관되어 있는지 확인합니다. 현재 API 플랜과 한도를 확인하세요.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

도메인, URL 또는 IP 주소의 FortiGuard 분류 및 위협 인텔리전스를 조회합니다. 이용 가능 여부는 서비스마다 다릅니다.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

IP 주소가 스팸 활동 신고로 등록되어 있는지 확인합니다.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

서비스 커뮤니티 및 기타 신호를 기반으로 한 도메인 평판 정보를 가져옵니다.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

IP 주소의 지리적 위치, ASN, 조직 및 관련 메타데이터를 가져옵니다. 할당량은 현재 플랜에서 확인하세요.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

이 플랫폼은 과거 DNS 해석 결과, IP 또는 name server와 연관된 도메인, 관련 레코드 등 DNS 및 인프라 인텔리전스를 제공합니다. 과거 DNS 기록에서 이전 origin 주소를 찾을 수 있지만, CDN을 안정적으로 우회하지는 못하므로 검증이 필요합니다.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

이메일 주소, 도메인 또는 회사 이름에 사용 가능한 신원 및 비즈니스 속성을 보강합니다. 개인정보는 허가 및 개인정보 보호 요건에 따라 처리하세요.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

RiskIQ의 PassiveTotal 기능은 Microsoft Defender Threat Intelligence로 이전되었습니다. 제품 접근 권한, API 및 유지되는 기능이 변경되었으므로, 이전 PassiveTotal 정보를 전제로 하지 말고 Microsoft의 최신 문서를 사용하세요.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

서비스의 접근 제어를 준수하여 도메인, IP 주소, 이메일 주소, 색인된 과거 데이터 또는 leaked 데이터를 검색합니다.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

IP 주소 및 기타 지표의 위협 인텔리전스와 평판 데이터를 검색합니다.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

인터넷 스캔 및 일반적인 서비스 활동에 대한 관측 정보를 IP 주소 또는 범위별로 검색합니다. 현재 체험판 및 커뮤니티 접근 조건을 확인하세요.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

IP 주소, host 또는 검색 쿼리에 대한 인터넷 스캔 및 서비스 정보를 가져옵니다. API 접근은 계정 플랜에 따라 달라집니다.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

host, 인증서, 도메인 및 인터넷 서비스 데이터셋을 검색합니다. 데이터 모델과 범위는 Shodan과 다릅니다.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

키워드로 공개적으로 관찰된 cloud-storage 객체 및 bucket에 대한 공급업체 색인을 검색합니다.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

색인된 침해 데이터에서 이메일 주소, 사용자 이름, 도메인 및 관련 레코드를 검색합니다. 허가된 경우에만 사용하고 침해 데이터가 불필요하게 노출되지 않도록 하세요.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

색인된 paste 콘텐츠에서 이메일 주소나 다른 용어가 포함된 항목을 검색합니다. 연동하기 전에 서비스가 여전히 제공되는지 확인하세요.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

이메일 주소의 평판 및 위험 신호를 가져옵니다.

## GhostProject (historical) <sup>[[24]](#references)</sup>

과거에 leaked 이메일/비밀번호 데이터 검색을 제공한다고 홍보했습니다. 제3자에게 데이터를 제공하는 위험이 큰 서비스로 간주하고, 사용 전에 서비스 제공 여부, 적법성 및 허가를 확인하세요.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

IP 주소 및 관련 자산의 인터넷 스캔, 노출 및 위협 인텔리전스 데이터를 가져옵니다.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

이메일 주소 또는 검증된 도메인이 알려진 침해 데이터에 포함되어 있는지 확인합니다. 별도의 Pwned Passwords 서비스는 접두사로 비밀번호 hash를 확인하며, 평문 비밀번호를 **노출하지 않습니다**.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

IP 지리적 위치, 데이터 센터, ASN, proxy/VPN 및 관련 정보 보강 필드를 가져옵니다. 할당량은 현재 플랜에 따라 달라집니다.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
일부 데이터 포인트를 제공하는 IP 지리적 위치 및 OSINT 기반 정보 보강 서비스입니다. 상업적 사용에 관한 최신 약관을 확인하세요.


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
- [24] [Cornell 연구 — 침해된 자격 증명 확인을 위한 프로토콜 (GhostProject 포함)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../../banners/hacktricks-training.md}}
