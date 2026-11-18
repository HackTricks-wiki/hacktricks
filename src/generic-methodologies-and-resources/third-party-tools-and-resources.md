# 第三方工具和资源

{{#include ../banners/hacktricks-training.md}}

本页面汇集了第三方工具和服务，并非推荐的测试方法论。请确认各项目的维护状态，并且仅在你获准评估的系统上使用工具；OWASP Web Security Testing Guide 提供了规划 Web 测试的结构化入门指南。<sup>[[1]](#references)</sup>

## BlueTeam

- [https://github.com/yarox24/attack_monitor](https://github.com/yarox24/attack_monitor)
- [https://capsule8.com/blog/dont-get-kicked-out-a-tale-of-rootkits-and-other-backdoors/](https://capsule8.com/blog/dont-get-kicked-out-a-tale-of-rootkits-and-other-backdoors/)
- [https://github.com/ION28/BLUESPAWN](https://github.com/ION28/BLUESPAWN)
- [https://github.com/PaperMtn/lil-pwny](https://github.com/PaperMtn/lil-pwny) : 检查泄露的账户
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
- [https://www.nmmapper.com/sys/tools/subdomainfinder/](https://www.nmmapper.com/sys/tools/subdomainfinder/) : 8 种子域名查找工具，包括 sublist3r、amass 等

## **WEB**

- [https://github.com/AlisamTechnology/ATSCAN](https://github.com/AlisamTechnology/ATSCAN)
- [https://github.com/momenbasel/KeyFinder](https://github.com/momenbasel/KeyFinder)
- [https://github.com/hahwul/XSpear](https://github.com/hahwul/XSpear)
- [https://github.com/BitTheByte/Monitorizer/](https://github.com/BitTheByte/Monitorizer/)
- [https://github.com/spinkham/skipfish](https://github.com/spinkham/skipfish)
- [https://github.com/blark/aiodnsbrute](https://github.com/blark/aiodnsbrute) : 异步暴力枚举域名
- [https://crt.sh/?q=%.yahoo.com](https://crt.sh/?q=%.yahoo.com) : 子域名暴力枚举
- [https://github.com/tomnomnom/httprobe](https://github.com/tomnomnom/httprobe): 检查域名下的 Web 服务器是否可访问
- [https://github.com/aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r) : 子域名发现
- [https://github.com/gwen001/github-search/blob/master/github-subdomains.py](https://github.com/gwen001/github-search/blob/master/github-subdomains.py) : 在 github 上发现子域名
- [https://github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) : 快速端口扫描
- [https://github.com/Threezh1/JSFinder](https://github.com/Threezh1/JSFinder) : 从网站的 JS 文件中提取子域名和 URL
- [https://github.com/C1h2e1/MyFuzzingDict](https://github.com/C1h2e1/MyFuzzingDict) : Web 文件字典
- [https://github.com/TypeError/Bookmarks/blob/master/README.md](https://github.com/TypeError/Bookmarks/blob/master/README.md) : BurpExtension，可避免打开几十个 repeater 标签页
- [https://github.com/hakluke/hakrawler](https://github.com/hakluke/hakrawler) : 获取资产
- [https://github.com/izo30/google-dorker](https://github.com/izo30/google-dorker) : Google dorks
- [https://github.com/sehno/Bug-bounty/blob/master/bugbounty_checklist.md](https://github.com/sehno/Bug-bounty/blob/master/bugbounty_checklist.md) : Web BugBounty 检查清单
- [https://github.com/Naategh/dom-red](https://github.com/Naategh/dom-red) : 检查域名列表是否存在 Open Redirection
- [https://github.com/prodigysml/Dr.-Watson](https://github.com/prodigysml/Dr.-Watson) : Burp 插件，可离线分析并发现域名、子域名和 IP
- [https://github.com/hahwul/WebHackersWeapons](https://github.com/hahwul/WebHackersWeapons): 各类工具列表
- [https://github.com/gauravnarwani97/Trishul](https://github.com/gauravnarwani97/Trishul) : 用于查找漏洞（SQLi、XSS、SSTI）的 Burp Suite 插件
- [https://github.com/fransr/postMessage-tracker](https://github.com/fransr/postMessage-tracker) : 用于追踪 post-message 函数的 Chrome 扩展
- [https://github.com/Quitten/Autorize](https://github.com/Quitten/Autorize) : 自动化身份验证测试（移除 cookies 并尝试发送请求）
- [https://github.com/pikpikcu/xrcross](https://github.com/pikpikcu/xrcross): XRCross 是一款用于重构、扫描以及 penetration / BugBounty 测试的工具。该工具旨在测试 (XSS|SSRF|CORS|SSTI|IDOR|RCE|LFI|SQLI) 漏洞

## Windows

- [https://github.com/Mr-Un1k0d3r/PoisonHandler](https://github.com/Mr-Un1k0d3r/PoisonHandler) : 横向移动
- [https://freddiebarrsmith.com/trix/trix.html](https://freddiebarrsmith.com/trix/trix.html) : LOL bins
- [https://gist.github.com/netbiosX/ee35fcd3722e401a38136cff7b751d79](https://gist.github.com/netbiosX/ee35fcd3722e401a38136cff7b751d79) ([https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/](https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/)): 持久化
- [https://github.com/odzhan/injection](https://github.com/odzhan/injection) : Windows 进程注入技术
- [https://github.com/BankSecurity/Red_Team](https://github.com/BankSecurity/Red_Team) : Red Team 脚本
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2) : 查找 Active Directory Group Policy 中与安全相关的错误配置。
- [https://www.wietzebeukema.nl/blog/powershell-obfuscation-using-securestring](https://www.wietzebeukema.nl/blog/powershell-obfuscation-using-securestring) : Securestring 混淆
- [https://pentestlab.blog/2020/02/24/parent-pid-spoofing/](https://pentestlab.blog/2020/02/24/parent-pid-spoofing/) : Parent PID Spoofing
- [https://github.com/the-xentropy/xencrypt](https://github.com/the-xentropy/xencrypt) : 加密 Powershell payload
- [https://shells.systems/introducing-ninja-c2-the-c2-built-for-stealth-red-team-operations/](https://shells.systems/introducing-ninja-c2-the-c2-built-for-stealth-red-team-operations/) : 隐蔽 C2
- [https://windows-internals.com/faxing-your-way-to-system/](https://windows-internals.com/faxing-your-way-to-system/) : 关于 Windows Internals 的系列日志
- [https://bestestredteam.com/2018/10/02/tracking-pixel-in-microsoft-office-document/](https://bestestredteam.com/2018/10/02/tracking-pixel-in-microsoft-office-document/) : 追踪谁打开了文档
- [https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet) : Active Directory 速查表

## Firmware

可用于自动化 firmware 分析的工具：

- [https://github.com/craigz28/firmwalker](https://github.com/craigz28/firmwalker)
- [https://github.com/fkie-cad/FACT_core](https://github.com/fkie-cad/FACT_core)
- [https://gitlab.com/bytesweep/bytesweep-go](https://gitlab.com/bytesweep/bytesweep-go)

Post-crema：

- [https://blog.mindedsecurity.com/2018/09/pentesting-iot-devices-part-1-static.html](https://blog.mindedsecurity.com/2018/09/pentesting-iot-devices-part-1-static.html)
- [https://blog.mindedsecurity.com/2018/10/pentesting-iot-devices-part-2-dynamic.html](https://blog.mindedsecurity.com/2018/10/pentesting-iot-devices-part-2-dynamic.html)

如果在线找不到 firmware，如何提取：[https://www.youtube.com/watch?v=Kxvpbu9STU4](https://www.youtube.com/watch?v=Kxvpbu9STU4)

这里有一个包含可供分析漏洞的 firmware：[https://github.com/scriptingxss/IoTGoat](https://github.com/scriptingxss/IoTGoat)

OWASP firmware 测试方法论：[https://github.com/scriptingxss/owasp-fstm](https://github.com/scriptingxss/owasp-fstm)

Firmware 仿真：FIRMADYNE (https://github.com/firmadyne/firmadyne/) 是一个用于自动化仿真和动态分析基于 Linux 的 firmware 平台。

## OTHER

- [https://twitter.com/HackAndDo/status/1202695084543791117](https://twitter.com/HackAndDo/status/1202695084543791117)
- [https://github.com/weev3/LKWA](https://github.com/weev3/LKWA)
- [https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/](https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/)
- [https://github.com/skelsec/jackdaw](https://github.com/skelsec/jackdaw)
- [https://github.com/CoatiSoftware/Sourcetrail](https://github.com/CoatiSoftware/Sourcetrail) : 静态代码分析
- [https://www.hackerdecabecera.com/2019/12/blectf-capture-flag-en-formato-hardware.html](https://www.hackerdecabecera.com/2019/12/blectf-capture-flag-en-formato-hardware.html) : Bluetooth LE CTF
- [https://github.com/skeeto/endlessh](https://github.com/skeeto/endlessh) : SSH tarpit，会缓慢地发送一个无休止的 banner。
- AWS 和 Cloud 工具：[https://github.com/toniblyx/my-arsenal-of-aws-security-tools](https://github.com/toniblyx/my-arsenal-of-aws-security-tools)
- 用于 phishing 的 IFS (Interplanetary File System)：[https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/using-the-interplanetary-file-system-for-offensive-operations/](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/using-the-interplanetary-file-system-for-offensive-operations/)
- IP 轮换服务：[https://medium.com/@lokeshdlk77/how-to-rotate-ip-address-in-brute-force-attack-e66407259212](https://medium.com/@lokeshdlk77/how-to-rotate-ip-address-in-brute-force-attack-e66407259212)
- Linux rootkit：[https://github.com/aesophor/satanic-rootkit](https://github.com/aesophor/satanic-rootkit)
- [https://theia-ide.org/](https://theia-ide.org) : 在线 IDE
- [https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/](https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/) : 入门 BugBounties 的资源
- [https://medium.com/macoclock/jailbreak-and-stuff-kickstart-tools-and-techniques-for-ios-application-pentesting-6fa53a3987ab](https://medium.com/macoclock/jailbreak-and-stuff-kickstart-tools-and-techniques-for-ios-application-pentesting-6fa53a3987ab) : IOS pentesting 工具
- [https://github.com/random-robbie/keywords/blob/master/keywords.txt](https://github.com/random-robbie/keywords/blob/master/keywords.txt) : 关键词
- [https://github.com/ElevenPaths/HomePWN](https://github.com/ElevenPaths/HomePWN) : IoT hacking（Wifi、BLE、SSDP、MDNS）
- [https://github.com/rackerlabs/scantron](https://github.com/rackerlabs/scantron) : 自动化扫描
- [https://github.com/doyensec/awesome-electronjs-hacking](https://github.com/doyensec/awesome-electronjs-hacking) : 此列表旨在涵盖 Electron.js 相关的安全主题。
- [https://github.com/serain/bbrecon](https://github.com/serain/bbrecon) : BB 项目信息

## References

- [1] [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
{{#include ../banners/hacktricks-training.md}}
