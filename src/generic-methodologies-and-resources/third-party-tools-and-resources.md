# 서드파티 도구 및 리소스

{{#include ../banners/hacktricks-training.md}}

이 페이지는 권장 테스트 방법론이 아니라 서드파티 도구와 서비스의 모음입니다. 각 프로젝트의 유지 관리 상태를 확인하고, 평가 권한이 있는 시스템에서만 도구를 사용하세요. OWASP Web Security Testing Guide는 웹 테스트 계획을 세우기 위한 체계적인 출발점을 제공합니다.<sup>[[1]](#references)</sup>

## BlueTeam

- [https://github.com/yarox24/attack_monitor](https://github.com/yarox24/attack_monitor)
- [https://capsule8.com/blog/dont-get-kicked-out-a-tale-of-rootkits-and-other-backdoors/](https://capsule8.com/blog/dont-get-kicked-out-a-tale-of-rootkits-and-other-backdoors/)
- [https://github.com/ION28/BLUESPAWN](https://github.com/ION28/BLUESPAWN)
- [https://github.com/PaperMtn/lil-pwny](https://github.com/PaperMtn/lil-pwny) : 유출된 계정 확인
- [https://github.com/rabobank-cdc/DeTTECT](https://github.com/rabobank-cdc/DeTTECT)

## OSINT

- [https://github.com/3vangel1st/kamerka](https://github.com/3vangel1st/kamerka)
- [https://github.com/BullsEye0/google_dork_list](https://github.com/BullsEye0/google_dork_list)
- [https://github.com/highmeh/lure](https://github.com/highmeh/lure)
- [https://www.shodan.io/](https://www.shodan.io)
- [https://censys.io/](https://censys.io)
- [https://webmii.com/](https://webmii.com/)
- [https://viz.greynoise.io/table](https://viz.greynoise.io/table)
- [https://www.zoomeye.org](https://www.zoomeye.org)
- [https://fofa.so](https://fofa.so)
- [https://www.onyphe.io](https://www.onyphe.io)
- [https://app.binaryedge.io](https://app.binaryedge.io)
- [https://hunter.io](https://hunter.io)
- [https://wigle.net](https://wigle.net)
- [https://ghostproject.fr](https://ghostproject.fr)
- [https://www.oshadan.com/](https://www.oshadan.com)
- [https://builtwith.com/](https://builtwith.com)
- [https://www.spiderfoot.net/](https://www.spiderfoot.net)
- [https://github.com/zricethezav/gitleaks](https://github.com/zricethezav/gitleaks)
- [https://www.nmmapper.com/sys/tools/subdomainfinder/](https://www.nmmapper.com/sys/tools/subdomainfinder/) : sublist3r, amass 등을 포함한 8가지 서브도메인 검색 도구

## **WEB**

- [https://github.com/AlisamTechnology/ATSCAN](https://github.com/AlisamTechnology/ATSCAN)
- [https://github.com/momenbasel/KeyFinder](https://github.com/momenbasel/KeyFinder)
- [https://github.com/hahwul/XSpear](https://github.com/hahwul/XSpear)
- [https://github.com/BitTheByte/Monitorizer/](https://github.com/BitTheByte/Monitorizer/)
- [https://github.com/spinkham/skipfish](https://github.com/spinkham/skipfish)
- [https://github.com/blark/aiodnsbrute](https://github.com/blark/aiodnsbrute) : 비동기 방식으로 도메인 이름 무차별 대입
- [https://crt.sh/?q=%.yahoo.com](https://crt.sh/?q=%.yahoo.com) : 서브도메인 무차별 대입
- [https://github.com/tomnomnom/httprobe](https://github.com/tomnomnom/httprobe): 도메인의 웹 서버에 액세스할 수 있는지 확인
- [https://github.com/aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r) : 서브도메인 탐색
- [https://github.com/gwen001/github-search/blob/master/github-subdomains.py](https://github.com/gwen001/github-search/blob/master/github-subdomains.py) : github에서 서브도메인 탐색
- [https://github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) : 빠른 포트 스캔
- [https://github.com/Threezh1/JSFinder](https://github.com/Threezh1/JSFinder) : 웹의 JS 파일에서 서브도메인과 URL 추출
- [https://github.com/C1h2e1/MyFuzzingDict](https://github.com/C1h2e1/MyFuzzingDict) : 웹 파일 사전
- [https://github.com/TypeError/Bookmarks/blob/master/README.md](https://github.com/TypeError/Bookmarks/blob/master/README.md) : 수십 개의 repeater 탭을 방지하는 BurpExtension
- [https://github.com/hakluke/hakrawler](https://github.com/hakluke/hakrawler) : 자산 수집
- [https://github.com/izo30/google-dorker](https://github.com/izo30/google-dorker) : Google dork
- [https://github.com/sehno/Bug-bounty/blob/master/bugbounty_checklist.md](https://github.com/sehno/Bug-bounty/blob/master/bugbounty_checklist.md) : 웹 BugBounty 체크리스트
- [https://github.com/Naategh/dom-red](https://github.com/Naategh/dom-red) : 도메인 목록에서 Open Redirection 확인
- [https://github.com/prodigysml/Dr.-Watson](https://github.com/prodigysml/Dr.-Watson) : 도메인, 서브도메인, IP를 찾는 오프라인 분석용 Burp 플러그인
- [https://github.com/hahwul/WebHackersWeapons](https://github.com/hahwul/WebHackersWeapons): 다양한 도구 목록
- [https://github.com/gauravnarwani97/Trishul](https://github.com/gauravnarwani97/Trishul) : 취약점(SQLi, XSS, SSTI) 탐지용 Burp Suite 플러그인
- [https://github.com/fransr/postMessage-tracker](https://github.com/fransr/postMessage-tracker) : post-message 함수 추적용 Chrome 확장 프로그램
- [https://github.com/Quitten/Autorize](https://github.com/Quitten/Autorize) : 자동 인증 테스트(쿠키를 제거하고 요청 전송 시도)
- [https://github.com/pikpikcu/xrcross](https://github.com/pikpikcu/xrcross): XRCross는 penetration / BugBounty 테스트를 위한 재구성, 스캐너 및 도구입니다. 이 도구는 (XSS|SSRF|CORS|SSTI|IDOR|RCE|LFI|SQLI) 취약점을 테스트하기 위해 만들어졌습니다.

## Windows

- [https://github.com/Mr-Un1k0d3r/PoisonHandler](https://github.com/Mr-Un1k0d3r/PoisonHandler) : 측면 이동
- [https://freddiebarrsmith.com/trix/trix.html](https://freddiebarrsmith.com/trix/trix.html) : LOL bins
- [https://gist.github.com/netbiosX/ee35fcd3722e401a38136cff7b751d79](https://gist.github.com/netbiosX/ee35fcd3722e401a38136cff7b751d79) ([https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/](https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/)): 지속성
- [https://github.com/odzhan/injection](https://github.com/odzhan/injection) : Windows Process Injection 기법
- [https://github.com/BankSecurity/Red_Team](https://github.com/BankSecurity/Red_Team) : Red Team 스크립트
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2) : Active Directory Group Policy의 보안 관련 잘못된 구성을 찾습니다.
- [https://www.wietzebeukema.nl/blog/powershell-obfuscation-using-securestring](https://www.wietzebeukema.nl/blog/powershell-obfuscation-using-securestring) : Securestring 난독화
- [https://pentestlab.blog/2020/02/24/parent-pid-spoofing/](https://pentestlab.blog/2020/02/24/parent-pid-spoofing/) : Parent PID Spoofing
- [https://github.com/the-xentropy/xencrypt](https://github.com/the-xentropy/xencrypt) : Powershell payload 암호화
- [https://shells.systems/introducing-ninja-c2-the-c2-built-for-stealth-red-team-operations/](https://shells.systems/introducing-ninja-c2-the-c2-built-for-stealth-red-team-operations/) : 은밀한 C2
- [https://windows-internals.com/faxing-your-way-to-system/](https://windows-internals.com/faxing-your-way-to-system/) : Windows Internals에 관한 로그 시리즈
- [https://bestestredteam.com/2018/10/02/tracking-pixel-in-microsoft-office-document/](https://bestestredteam.com/2018/10/02/tracking-pixel-in-microsoft-office-document/) : 문서를 연 사람 추적
- [https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet) : Active Directory Cheat Sheet

## Firmware

Firmware 분석을 자동화하는 데 도움이 될 수 있는 도구:

- [https://github.com/craigz28/firmwalker](https://github.com/craigz28/firmwalker)
- [https://github.com/fkie-cad/FACT_core](https://github.com/fkie-cad/FACT_core)
- [https://gitlab.com/bytesweep/bytesweep-go](https://gitlab.com/bytesweep/bytesweep-go)

Post-crema:

- [https://blog.mindedsecurity.com/2018/09/pentesting-iot-devices-part-1-static.html](https://blog.mindedsecurity.com/2018/09/pentesting-iot-devices-part-1-static.html)
- [https://blog.mindedsecurity.com/2018/10/pentesting-iot-devices-part-2-dynamic.html](https://blog.mindedsecurity.com/2018/10/pentesting-iot-devices-part-2-dynamic.html)

Como extraer firmware si no lo encontramos online: [https://www.youtube.com/watch?v=Kxvpbu9STU4](https://www.youtube.com/watch?v=Kxvpbu9STU4)

Aqui un firware con vulnerabilidades para analizar: [https://github.com/scriptingxss/IoTGoat](https://github.com/scriptingxss/IoTGoat)

OWASP firmware-testing methodology: [https://github.com/scriptingxss/owasp-fstm](https://github.com/scriptingxss/owasp-fstm)

Firmware 에뮬레이션: FIRMADYNE (https://github.com/firmadyne/firmadyne/)는 Linux 기반 firmware의 에뮬레이션과 동적 분석을 자동화하는 플랫폼입니다.

## OTHER

- [https://twitter.com/HackAndDo/status/1202695084543791117](https://twitter.com/HackAndDo/status/1202695084543791117)
- [https://github.com/weev3/LKWA](https://github.com/weev3/LKWA)
- [https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/](https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/)
- [https://github.com/skelsec/jackdaw](https://github.com/skelsec/jackdaw)
- [https://github.com/CoatiSoftware/Sourcetrail](https://github.com/CoatiSoftware/Sourcetrail) : 정적 코드 분석
- [https://www.hackerdecabecera.com/2019/12/blectf-capture-flag-en-formato-hardware.html](https://www.hackerdecabecera.com/2019/12/blectf-capture-flag-en-formato-hardware.html) : Bluetooth LE CTF
- [https://github.com/skeeto/endlessh](https://github.com/skeeto/endlessh) : 끝없는 배너를 느리게 전송하는 SSH tarpit.
- AWS 및 Cloud 도구: [https://github.com/toniblyx/my-arsenal-of-aws-security-tools](https://github.com/toniblyx/my-arsenal-of-aws-security-tools)
- 피싱용 IFS (Interplanetary File System): [https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/using-the-interplanetary-file-system-for-offensive-operations/](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/using-the-interplanetary-file-system-for-offensive-operations/)
- IP rotation 서비스: [https://medium.com/@lokeshdlk77/how-to-rotate-ip-address-in-brute-force-attack-e66407259212](https://medium.com/@lokeshdlk77/how-to-rotate-ip-address-in-brute-force-attack-e66407259212)
- Linux rootkit: [https://github.com/aesophor/satanic-rootkit](https://github.com/aesophor/satanic-rootkit)
- [https://theia-ide.org/](https://theia-ide.org) : 온라인 IDE
- [https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/](https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/) : BugBounty를 시작하기 위한 리소스
- [https://medium.com/macoclock/jailbreak-and-stuff-kickstart-tools-and-techniques-for-ios-application-pentesting-6fa53a3987ab](https://medium.com/macoclock/jailbreak-and-stuff-kickstart-tools-and-techniques-for-ios-application-pentesting-6fa53a3987ab) : IOS pentesting 도구
- [https://github.com/random-robbie/keywords/blob/master/keywords.txt](https://github.com/random-robbie/keywords/blob/master/keywords.txt) : 키워드
- [https://github.com/ElevenPaths/HomePWN](https://github.com/ElevenPaths/HomePWN) : IoT 해킹(Wifi, BLE, SSDP, MDNS)
- [https://github.com/rackerlabs/scantron](https://github.com/rackerlabs/scantron) : 스캔 자동화
- [https://github.com/doyensec/awesome-electronjs-hacking](https://github.com/doyensec/awesome-electronjs-hacking) : Electron.js 보안 관련 주제를 다루는 목록입니다.
- [https://github.com/serain/bbrecon](https://github.com/serain/bbrecon) : BB 프로그램 정보

## References

- [1] [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
{{#include ../banners/hacktricks-training.md}}
