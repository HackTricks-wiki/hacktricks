# サードパーティのツールとリソース

{{#include ../banners/hacktricks-training.md}}

このページは、推奨されるテスト方法ではなく、サードパーティのツールやサービスを集めたものです。各プロジェクトのメンテナンス状況を確認し、評価の許可を得たシステムでのみツールを使用してください。Webテストの計画を立てる際は、OWASP Web Security Testing Guideが体系的な出発点になります。<sup>[[1]](#references)</sup>

## BlueTeam

- [https://github.com/yarox24/attack_monitor](https://github.com/yarox24/attack_monitor)
- [https://capsule8.com/blog/dont-get-kicked-out-a-tale-of-rootkits-and-other-backdoors/](https://capsule8.com/blog/dont-get-kicked-out-a-tale-of-rootkits-and-other-backdoors/)
- [https://github.com/ION28/BLUESPAWN](https://github.com/ION28/BLUESPAWN)
- [https://github.com/PaperMtn/lil-pwny](https://github.com/PaperMtn/lil-pwny) : 漏洩したアカウントを確認
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
- [https://www.nmmapper.com/sys/tools/subdomainfinder/](https://www.nmmapper.com/sys/tools/subdomainfinder/) : sublist3r、amassなど、8種類のSubdomain finderツール

## **WEB**

- [https://github.com/AlisamTechnology/ATSCAN](https://github.com/AlisamTechnology/ATSCAN)
- [https://github.com/momenbasel/KeyFinder](https://github.com/momenbasel/KeyFinder)
- [https://github.com/hahwul/XSpear](https://github.com/hahwul/XSpear)
- [https://github.com/BitTheByte/Monitorizer/](https://github.com/BitTheByte/Monitorizer/)
- [https://github.com/spinkham/skipfish](https://github.com/spinkham/skipfish)
- [https://github.com/blark/aiodnsbrute](https://github.com/blark/aiodnsbrute) : 非同期でドメイン名をBrute force
- [https://crt.sh/?q=%.yahoo.com](https://crt.sh/?q=%.yahoo.com) : SubdomainのBrute force
- [https://github.com/tomnomnom/httprobe](https://github.com/tomnomnom/httprobe): ドメイン内のWebサーバーにアクセスできるか確認
- [https://github.com/aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r) : Subdomainの発見
- [https://github.com/gwen001/github-search/blob/master/github-subdomains.py](https://github.com/gwen001/github-search/blob/master/github-subdomains.py) : GitHub上でSubdomainを発見
- [https://github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) : 高速なポートスキャン
- [https://github.com/Threezh1/JSFinder](https://github.com/Threezh1/JSFinder) : WebサイトのJSファイルからSubdomainとURLを取得
- [https://github.com/C1h2e1/MyFuzzingDict](https://github.com/C1h2e1/MyFuzzingDict) : Webファイル用の辞書
- [https://github.com/TypeError/Bookmarks/blob/master/README.md](https://github.com/TypeError/Bookmarks/blob/master/README.md) : Repeaterタブが大量に開くのを防ぐBurpExtension
- [https://github.com/hakluke/hakrawler](https://github.com/hakluke/hakrawler) : アセットを取得
- [https://github.com/izo30/google-dorker](https://github.com/izo30/google-dorker) : Google dorks
- [https://github.com/sehno/Bug-bounty/blob/master/bugbounty_checklist.md](https://github.com/sehno/Bug-bounty/blob/master/bugbounty_checklist.md) : Web BugBountyチェックリスト
- [https://github.com/Naategh/dom-red](https://github.com/Naategh/dom-red) : ドメインのリストをOpen Redirectionについて確認
- [https://github.com/prodigysml/Dr.-Watson](https://github.com/prodigysml/Dr.-Watson) : ドメイン、Subdomain、IPを見つけるオフライン分析用Burpプラグイン
- [https://github.com/hahwul/WebHackersWeapons](https://github.com/hahwul/WebHackersWeapons): さまざまなツールの一覧
- [https://github.com/gauravnarwani97/Trishul](https://github.com/gauravnarwani97/Trishul) : 脆弱性（SQLi、XSS、SSTI）を見つけるBurp Suiteプラグイン
- [https://github.com/fransr/postMessage-tracker](https://github.com/fransr/postMessage-tracker) : post-message関数を追跡するChrome拡張機能
- [https://github.com/Quitten/Autorize](https://github.com/Quitten/Autorize) : 自動認証テスト（cookieを削除してリクエストの送信を試行）
- [https://github.com/pikpikcu/xrcross](https://github.com/pikpikcu/xrcross): XRCrossは、ペネトレーションテストやBugBountyテスト用の再構築・スキャナー・ツールです。XSS、SSRF、CORS、SSTI、IDOR、RCE、LFI、SQLIの脆弱性テスト向けに作られています。

## Windows

- [https://github.com/Mr-Un1k0d3r/PoisonHandler](https://github.com/Mr-Un1k0d3r/PoisonHandler) : Lateral movement
- [https://freddiebarrsmith.com/trix/trix.html](https://freddiebarrsmith.com/trix/trix.html) : LOL bins
- [https://gist.github.com/netbiosX/ee35fcd3722e401a38136cff7b751d79](https://gist.github.com/netbiosX/ee35fcd3722e401a38136cff7b751d79) ([https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/](https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/)): Persistence
- [https://github.com/odzhan/injection](https://github.com/odzhan/injection) : Windows Process Injectionの手法
- [https://github.com/BankSecurity/Red_Team](https://github.com/BankSecurity/Red_Team) : Red Teamスクリプト
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2) : Active Directory Group Policyのセキュリティ関連の設定ミスを検出
- [https://www.wietzebeukema.nl/blog/powershell-obfuscation-using-securestring](https://www.wietzebeukema.nl/blog/powershell-obfuscation-using-securestring) : Securestringの難読化
- [https://pentestlab.blog/2020/02/24/parent-pid-spoofing/](https://pentestlab.blog/2020/02/24/parent-pid-spoofing/) : Parent PID Spoofing
- [https://github.com/the-xentropy/xencrypt](https://github.com/the-xentropy/xencrypt) : PowerShell payloadsを暗号化
- [https://shells.systems/introducing-ninja-c2-the-c2-built-for-stealth-red-team-operations/](https://shells.systems/introducing-ninja-c2-the-c2-built-for-stealth-red-team-operations/) : ステルス性の高いC2
- [https://windows-internals.com/faxing-your-way-to-system/](https://windows-internals.com/faxing-your-way-to-system/) : Windows Internalsに関するログのシリーズ
- [https://bestestredteam.com/2018/10/02/tracking-pixel-in-microsoft-office-document/](https://bestestredteam.com/2018/10/02/tracking-pixel-in-microsoft-office-document/) : 誰がドキュメントを開いたか追跡
- [https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet) : Active Directory Cheat Sheet

## ファームウェア

ファームウェア分析の自動化に役立つツール:

- [https://github.com/craigz28/firmwalker](https://github.com/craigz28/firmwalker)
- [https://github.com/fkie-cad/FACT_core](https://github.com/fkie-cad/FACT_core)
- [https://gitlab.com/bytesweep/bytesweep-go](https://gitlab.com/bytesweep/bytesweep-go)

Post-crema:

- [https://blog.mindedsecurity.com/2018/09/pentesting-iot-devices-part-1-static.html](https://blog.mindedsecurity.com/2018/09/pentesting-iot-devices-part-1-static.html)
- [https://blog.mindedsecurity.com/2018/10/pentesting-iot-devices-part-2-dynamic.html](https://blog.mindedsecurity.com/2018/10/pentesting-iot-devices-part-2-dynamic.html)

オンラインで見つからない場合にファームウェアを抽出する方法: [https://www.youtube.com/watch?v=Kxvpbu9STU4](https://www.youtube.com/watch?v=Kxvpbu9STU4)

分析用の脆弱なファームウェアはこちら: [https://github.com/scriptingxss/IoTGoat](https://github.com/scriptingxss/IoTGoat)

OWASPファームウェアテスト方法論: [https://github.com/scriptingxss/owasp-fstm](https://github.com/scriptingxss/owasp-fstm)

ファームウェアのエミュレーション: FIRMADYNE (https://github.com/firmadyne/firmadyne/) は、Linuxベースのファームウェアのエミュレーションと動的分析を自動化するプラットフォームです。

## その他

- [https://twitter.com/HackAndDo/status/1202695084543791117](https://twitter.com/HackAndDo/status/1202695084543791117)
- [https://github.com/weev3/LKWA](https://github.com/weev3/LKWA)
- [https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/](https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/)
- [https://github.com/skelsec/jackdaw](https://github.com/skelsec/jackdaw)
- [https://github.com/CoatiSoftware/Sourcetrail](https://github.com/CoatiSoftware/Sourcetrail) : 静的コード解析
- [https://www.hackerdecabecera.com/2019/12/blectf-capture-flag-en-formato-hardware.html](https://www.hackerdecabecera.com/2019/12/blectf-capture-flag-en-formato-hardware.html) : Bluetooth LE CTF
- [https://github.com/skeeto/endlessh](https://github.com/skeeto/endlessh) : 終わりのないバナーをゆっくり送信するSSH tarpit
- AWSおよびCloudツール: [https://github.com/toniblyx/my-arsenal-of-aws-security-tools](https://github.com/toniblyx/my-arsenal-of-aws-security-tools)
- フィッシング用のIFS（Interplanetary File System）: [https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/using-the-interplanetary-file-system-for-offensive-operations/](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/using-the-interplanetary-file-system-for-offensive-operations/)
- IPローテーションサービス: [https://medium.com/@lokeshdlk77/how-to-rotate-ip-address-in-brute-force-attack-e66407259212](https://medium.com/@lokeshdlk77/how-to-rotate-ip-address-in-brute-force-attack-e66407259212)
- Linux rootkit: [https://github.com/aesophor/satanic-rootkit](https://github.com/aesophor/satanic-rootkit)
- [https://theia-ide.org/](https://theia-ide.org) : オンラインIDE
- [https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/](https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/) : BugBountyを始めるためのリソース
- [https://medium.com/macoclock/jailbreak-and-stuff-kickstart-tools-and-techniques-for-ios-application-pentesting-6fa53a3987ab](https://medium.com/macoclock/jailbreak-and-stuff-kickstart-tools-and-techniques-for-ios-application-pentesting-6fa53a3987ab) : iOS pentestingツール
- [https://github.com/random-robbie/keywords/blob/master/keywords.txt](https://github.com/random-robbie/keywords/blob/master/keywords.txt) : キーワード
- [https://github.com/ElevenPaths/HomePWN](https://github.com/ElevenPaths/HomePWN) : IoTのHacking（WiFi、BLE、SSDP、MDNS）
- [https://github.com/rackerlabs/scantron](https://github.com/rackerlabs/scantron) : スキャンの自動化
- [https://github.com/doyensec/awesome-electronjs-hacking](https://github.com/doyensec/awesome-electronjs-hacking) : Electron.jsのセキュリティ関連トピックを網羅することを目的とした一覧
- [https://github.com/serain/bbrecon](https://github.com/serain/bbrecon) : BBプログラムに関する情報

## References

- [1] [OWASP Webセキュリティテストガイド](https://owasp.org/www-project-web-security-testing-guide/)
{{#include ../banners/hacktricks-training.md}}
