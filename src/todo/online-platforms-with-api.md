# Majukwaa ya Mtandaoni yenye API

{{#include ../banners/hacktricks-training.md}}

Huduma hizi huwezesha workflows za reconnaissance, reputation, breach, au enrichment. API, quotas, bei, na matumizi yanayoruhusiwa hubadilika mara kwa mara; thibitisha nyaraka za sasa za vendor na authorization ya engagement kabla ya kutuma vitambulisho vya wateja au data nyeti.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Uliza ikiwa IP address imehusishwa na shughuli za kutiliwa shaka au hasidi. Access inaweza kuhitaji account au API key.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Kagua ikiwa IP address, username, au email address imehusishwa na usajili wa akaunti kiotomatiki au shughuli nyingine za bot zilizoripotiwa.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Tafuta na uthibitishe email addresses za kikazi na mifumo ya mawasiliano inayohusiana na domains. Kagua mpango wa sasa kwa request limits na matumizi yanayoruhusiwa.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Tafuta threat-intelligence indicators na shughuli zinazohusishwa na IP addresses na domains.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Ongeza data ya biashara/profile inayopatikana kwenye email address, domain, au kampuni. Coverage, access, na masharti ya faragha hutegemea product na plan ya sasa.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Tambua technologies zinazoonekana kwenye websites na upate data ya kihistoria au ya mahusiano pale ambapo plan iliyochaguliwa inaruhusu.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Kagua ikiwa IP address inahusishwa na shughuli za kutiliwa shaka au hasidi. Thibitisha API plans na limits za sasa.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Tafuta uainishaji wa FortiGuard na threat intelligence kwa domains, URLs, au IP addresses. Upatikanaji hutofautiana kulingana na service.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Kagua ikiwa IP address imeorodheshwa kwa shughuli za spam zilizoripotiwa.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Pata reputation ya domain kulingana na community ya service na signals nyingine.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Pata geolocation, ASN, organization, na metadata inayohusiana na IP address. Kagua quotas za plan ya sasa.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Platform hii hutoa DNS na infrastructure intelligence kama vile historical resolutions, domains zinazohusishwa na IPs au name servers, na records zinazohusiana. Historical DNS inaweza kufichua origin address ya awali, lakini haiwezi reliably bypass CDN na lazima ithibitishwe.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Ongeza identity na business attributes zinazopatikana kwenye email address, domain, au jina la kampuni. Shughulikia personal data kulingana na authorization na mahitaji ya faragha.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

Uwezo wa RiskIQ's PassiveTotal ulihamia Microsoft Defender Threat Intelligence. Product access, APIs, na functionality iliyohifadhiwa imebadilika, kwa hiyo tumia nyaraka za sasa za Microsoft badala ya assumptions za legacy PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Tafuta domains, IP addresses, email addresses, na data ya kihistoria au leaked iliyo-indexiwa, kwa kuzingatia access controls za service.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Tafuta IP addresses na indicators nyingine kwa threat-intelligence na reputation data.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Tafuta IP addresses au ranges kwa observations za internet scanning na shughuli za kawaida za services. Kagua masharti ya sasa ya trial na community access.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Pata taarifa za internet-scan na services kwa IP address, host, au search query. API access hutegemea account plan.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Tafuta datasets za hosts, certificates, domains, na internet services; data model na coverage yake hutofautiana na za Shodan.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Tafuta kwenye index ya provider ya cloud-storage objects na buckets zilizoonekana hadharani kwa kutumia keyword.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Tafuta breach data iliyo-indexiwa kwa email addresses, usernames, domains, na records zinazohusiana. Tumia tu ukiwa na authorization na epuka kufichua breach data isiyohitajika.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Tafuta paste content iliyo-indexiwa kwa occurrences za email address au neno jingine. Thibitisha kuwa service bado inapatikana kabla ya kui-integrate.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Pata reputation na risk signals za email address.

## GhostProject (historical) <sup>[[24]](#references)</sup>

Kihistoria ilitangaza searches za leaked email/password data. Ichukulie service hii kama third-party handling yenye risk kubwa na thibitisha upatikanaji, uhalali, na authorization yake kabla ya kuitumia.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Pata internet-scan, exposure, na threat-intelligence data kwa IP addresses na assets zinazohusiana.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Kagua ikiwa email address au verified domain inaonekana kwenye breaches zinazojulikana. Service tofauti ya Pwned Passwords hukagua password hashes kwa prefix; **haifichui** plaintext passwords.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Pata IP geolocation, data-center, ASN, proxy/VPN, na fields nyingine za enrichment. Quotas hutegemea plan ya sasa.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
IP geolocation na enrichment inayolenga OSINT yenye data points zilizochaguliwa. Kagua masharti ya sasa kuhusu matumizi ya kibiashara.


[DNSDumpster](https://dnsdumpster.com/) hutoa matokeo ya DNS-reconnaissance.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) hutoa site, hosting, na internet-infrastructure intelligence.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) hutoa interface ya mtandaoni ya subdomain-discovery.<sup>[[31]](#references)</sup>

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
- [24] [Cornell research — Protocols for Checking Compromised Credentials (includes GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../banners/hacktricks-training.md}}
