# Uundaji wa Mfano wa Tishio

{{#include ../banners/hacktricks-training.md}}

Karibu kwenye mwongozo mpana wa HackTricks kuhusu Uundaji wa Mfano wa Tishio! Anza kuchunguza kipengele hiki muhimu cha cybersecurity, ambapo tunatambua, kuelewa, na kupanga mikakati dhidi ya vulnerabilities zinazoweza kutokea katika mfumo. Sehemu hii ni mwongozo wa hatua kwa hatua uliojaa mifano ya ulimwengu halisi, software muhimu, na maelezo rahisi kueleweka. Unafaa kwa wanaoanza na wataalamu wenye uzoefu wanaotaka kuimarisha ulinzi wao wa cybersecurity.

### Matukio Yanayotumiwa Mara kwa Mara

1. **Uundaji wa Software**: Kama sehemu ya Secure Software Development Life Cycle (SSDLC), threat modeling husaidia katika **kutambua vyanzo vinavyoweza kusababisha vulnerabilities** katika hatua za awali za uundaji.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) huchukulia threat modeling kuwa hitaji la utekelezaji sahihi na huhitaji kurekodi assets za biashara, michakato ya biashara, jumuiya za vitisho, na uwezo wao.<sup>[[2]](#references)</sup>

### Threat Model kwa Muhtasari

Threat model kwa kawaida huwakilishwa na mchoro, picha, au kielelezo kingine cha kuona cha architecture iliyopangwa au application iliyopo. Data-flow diagrams (DFDs) ni njia ya kawaida ya kuunda model ya mfumo na mwingiliano wake, huku threat modeling ikiongeza uchanganuzi unaolenga usalama.<sup>[[1]](#references)</sup>

Katika Microsoft's Threat Modeling Tool, mistari yenye nukta nyekundu huonyesha mipaka ya uaminifu; tools nyingine zinaweza kutumia kanuni tofauti za kuona.<sup>[[4]](#references)</sup> Ili kurahisisha utambuzi wa risks, teams zinaweza kutumia triad ya CIA (Confidentiality, Integrity, Availability) au makundi ya threats ya STRIDE, lakini methodology inayofaa hutegemea muktadha na mahitaji ya project.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### Triad ya CIA

Triad ya CIA ni model inayotambulika sana ya information-security inayowakilisha Confidentiality, Integrity, na Availability. Sifa hizi hutumiwa kwa kawaida kueleza malengo ya usalama kwa data na systems.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Kuhakikisha kuwa data au mfumo haufikiwi na watu wasioidhinishwa. Hiki ni kipengele cha msingi cha usalama, kinachohitaji access controls zinazofaa, encryption, na hatua nyingine za kuzuia data breaches.
2. **Integrity**: Usahihi, uthabiti, na uaminifu wa data katika kipindi chote cha maisha yake. Kanuni hii huhakikisha kuwa data haibadilishwi au kuchezewa na wahusika wasioidhinishwa. Mara nyingi huhusisha checksums, hashing, na methods nyingine za kuthibitisha data.
3. **Availability**: Huhakikisha kuwa data na services zinapatikana kwa users walioidhinishwa zinapohitajika. Hili mara nyingi huhusisha redundancy, fault tolerance, na configurations za high-availability ili kuweka systems zikiendelea kufanya kazi hata zinapokumbwa na disruptions.

### Methodologies za Threat Modeling

1. **STRIDE**: Mbinu ya Microsoft's STRIDE huainisha threats za software kama **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, na Elevation of Privilege**. Makundi haya huwasaidia analysts kutambua threats zinazowezekana katika kila sehemu iliyo vulnerable ya design.<sup>[[5]](#references)</sup>
2. **DREAD**: Mbinu hii ya Microsoft ya assessment hupima threats kwa kutumia **Damage, Reproducibility, Exploitability, Affected users, na Discoverability**. Score inayopatikana inaweza kusaidia kupanga kipaumbele cha threats kwa ajili ya mitigation.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Hii ni methodology ya hatua saba, inayolenga **risk**, inayohusisha objectives, technical scope, application decomposition, threat analysis, vulnerability and weakness analysis, attack modeling, na risk/impact analysis.<sup>[[8]](#references)</sup>
4. **Trike**: Framework hii ya security-audit hushughulikia threat modeling kwa mtazamo wa **risk-management** na ulinzi.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Method hii inasisitiza threat models zinazoweza kupanuka na kutumika kwa urahisi kwa mitazamo ya application na operations, na inaweza kuunganishwa na development na DevOps lifecycles.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Iliyoundwa na CERT Division ya Carnegie Mellon's Software Engineering Institute, OCTAVE ni method ya kimkakati ya assessment na planning inayotegemea risk, inayolenga risk ya shirika badala ya technology pekee.<sup>[[10]](#references)</sup>

## Tools

Kuna tools na software solutions kadhaa zinazopatikana ambazo zinaweza **kusaidia** katika kuunda na kusimamia threat models. Hapa kuna baadhi unazoweza kuzingatia.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite ni web crawler ya cross-platform kwa wataalamu wa security inayosaidia attack-surface mapping, endpoint discovery, na web-application analysis.<sup>[[6]](#references)</sup>

**Matumizi**

1. Chagua URL na Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Tazama Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon ni application ya bure, ya open-source, na ya cross-platform ya threat-modeling kwa kuchora diagrams, kupendekeza threats, na kurekodi mitigations. Inapatikana kama web application na desktop application.<sup>[[7]](#references)</sup>

**Matumizi**

1. Unda Project Mpya

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Wakati mwingine inaweza kuonekana hivi:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Fungua Project Mpya

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Hifadhi Project Mpya

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Unda model yako

Unaweza kutumia tools kama SpiderSuite Crawler kupata msukumo; model ya msingi inaweza kuonekana kama hii

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Hapa kuna maelezo mafupi kuhusu entities:

- Process (Entity yenyewe kama vile Webserver au web functionality)
- Actor (Mtu kama Website Visitor, User au Administrator)
- Data Flow Line (Kiashiria cha Interaction)
- Trust Boundary (Network segments au scopes tofauti.)
- Store (Maeneo ambako data huhifadhiwa kama vile Databases)

5. Unda Threat (Hatua ya 1)

Kwanza unapaswa kuchagua layer unayotaka kuongeza threat

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Sasa unaweza kuunda threat

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Kumbuka kuwa kuna tofauti kati ya Actor Threats na Process Threats. Ukiongeza threat kwa Actor, utaweza kuchagua tu "Spoofing" na "Repudiation". Hata hivyo, katika mfano wetu tunaongeza threat kwa Process entity, kwa hiyo tutaona hivi katika threat creation box:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Imekamilika

Sasa model yako iliyokamilika inapaswa kuonekana kama hii. Hivi ndivyo unavyounda threat model rahisi kwa kutumia OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft's Threat Modeling Tool ni tool ya bure inayoweza kupakuliwa kwa ajili ya uchanganuzi wa software design. Workflow yake huunda diagram, hutambua threats, na kusaidia katika mitigation na validation kwa kutumia mbinu ya STRIDE.<sup>[[4]](#references)</sup>

## References

- [1] [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Threat Modeling - The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Security fundamentals - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Getting Started with the Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Threat Modeling for Drivers - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [PASTA Threat Modeling: The 7 Stages Explained](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Trike v1 Methodology Document](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Threat Modeling: A Summary of Available Methods](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
