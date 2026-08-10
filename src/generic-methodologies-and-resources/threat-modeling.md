# Uundaji wa Miundo ya Vitisho

Karibu kwenye mwongozo wa kina wa HackTricks kuhusu Threat Modeling! Anza kuchunguza kipengele hiki muhimu cha cybersecurity, ambapo tunatambua, kuelewa, na kupanga mikakati dhidi ya vulnerabilities zinazoweza kutokea kwenye mfumo. Mwongozo huu unatoa maelekezo ya hatua kwa hatua yaliyojaa mifano ya ulimwengu halisi, software muhimu, na maelezo rahisi kueleweka. Unafaa kwa wanaoanza na wataalamu wenye uzoefu wanaotaka kuimarisha ulinzi wao wa cybersecurity.

### Matukio Yanayotumika Mara kwa Mara

1. **Utengenezaji wa Software**: Kama sehemu ya Secure Software Development Life Cycle (SSDLC), threat modeling husaidia katika **kutambua vyanzo vinavyoweza kusababisha vulnerabilities** katika hatua za awali za utengenezaji.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) huchukulia threat modeling kuwa hitaji la utekelezaji sahihi na huhitaji kuandikwa kwa business assets, business processes, threat communities, na uwezo wao.<sup>[[2]](#references)</sup>

### Threat Model kwa Ufupi

Threat model kwa kawaida huwakilishwa kwa diagramu, picha, au mchoro mwingine wa kuona unaoonyesha architecture iliyopangwa au application iliyopo. Data-flow diagrams (DFDs) ni njia ya kawaida ya kuiga mfumo na mwingiliano wake, huku threat modeling ikiongeza uchanganuzi unaolenga usalama.<sup>[[1]](#references)</sup>

Katika Microsoft's Threat Modeling Tool, mistari myekundu yenye vitone huonyesha trust boundaries; tools nyingine zinaweza kutumia kanuni tofauti za kuona.<sup>[[4]](#references)</sup> Ili kurahisisha utambuzi wa risks, teams zinaweza kutumia CIA (Confidentiality, Integrity, Availability) triad au STRIDE threat categories, lakini methodology inayofaa hutegemea muktadha na mahitaji ya project.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### CIA Triad

CIA Triad ni model inayotambulika kwa upana katika information security, inayowakilisha Confidentiality, Integrity, na Availability. Sifa hizi hutumiwa kwa kawaida kueleza malengo ya usalama kwa data na systems.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Kuhakikisha kuwa data au system haifikiwi na watu wasioidhinishwa. Hiki ni kipengele cha msingi cha usalama, kinachohitaji access controls zinazofaa, encryption, na hatua nyingine za kuzuia data breaches.
2. **Integrity**: Usahihi, uthabiti, na uaminifu wa data katika kipindi chote cha lifecycle yake. Kanuni hii huhakikisha kuwa data haibadilishwi au kuchezewa na parties wasioidhinishwa. Mara nyingi huhusisha checksums, hashing, na mbinu nyingine za verification ya data.
3. **Availability**: Huhakikisha kuwa data na services zinapatikana kwa users walioidhinishwa zinapohitajika. Mara nyingi huhusisha redundancy, fault tolerance, na high-availability configurations ili systems ziendelee kufanya kazi hata zinapokabiliwa na disruptions.

### Threat Modeling Methodologies

1. **STRIDE**: Mbinu ya Microsoft ya STRIDE huainisha software threats kama **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, na Elevation of Privilege**. Categories hizi huwasaidia analysts kutambua threats zinazowezekana katika kila sehemu iliyo hatarini kwenye design.<sup>[[5]](#references)</sup>
2. **DREAD**: Mbinu hii ya Microsoft ya assessment hupima threats kwa kutumia **Damage, Reproducibility, Exploitability, Affected users, na Discoverability**. Score inayopatikana inaweza kusaidia kupanga kipaumbele cha threats kwa ajili ya mitigation.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Hii ni methodology ya hatua saba, inayolenga **risk-centric**, inayohusisha objectives, technical scope, application decomposition, threat analysis, vulnerability and weakness analysis, attack modeling, na risk/impact analysis.<sup>[[8]](#references)</sup>
4. **Trike**: Framework hii ya security-audit huangalia threat modeling kwa mtazamo wa **risk-management** na defensive.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Method hii inasisitiza threat models zinazoweza kupanuka na zinazotumika kwa urahisi kwa application na operational views, na inaweza kuunganishwa na development na DevOps lifecycles.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Iliundwa na CERT Division ya Carnegie Mellon's Software Engineering Institute, OCTAVE ni method ya strategic assessment na planning inayotegemea risk, inayolenga organizational risk badala ya technology pekee.<sup>[[10]](#references)</sup>

## Tools

Kuna tools na software solutions kadhaa zinazopatikana ambazo zinaweza **kusaidia** katika kuunda na kusimamia threat models. Hapa kuna baadhi unazoweza kuzingatia.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite ni web crawler ya cross-platform kwa security professionals inayosaidia attack-surface mapping, endpoint discovery, na web-application analysis.<sup>[[6]](#references)</sup>

**Matumizi**

1. Chagua URL na Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Tazama Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon ni application ya bure, open-source, na cross-platform ya threat-modeling kwa kuchora diagrams, kupendekeza threats, na kurekodi mitigations. Inapatikana kama web na desktop applications.<sup>[[7]](#references)</sup>

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

Unaweza kutumia tools kama SpiderSuite Crawler kupata mawazo; model ya msingi inaweza kuonekana hivi

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Hapa kuna maelezo mafupi kuhusu entities:

- Process (Entity yenyewe, kama Webserver au web functionality)
- Actor (Mtu, kama Website Visitor, User au Administrator)
- Data Flow Line (Kiashiria cha Interaction)
- Trust Boundary (Network segments au scopes tofauti.)
- Store (Sehemu ambako data huhifadhiwa, kama Databases)

5. Unda Threat (Hatua ya 1)

Kwanza lazima uchague layer unayotaka kuongeza threat

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Sasa unaweza kuunda threat

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Kumbuka kuwa kuna tofauti kati ya Actor Threats na Process Threats. Ukiongeza threat kwa Actor utaweza kuchagua tu "Spoofing" na "Repudiation". Hata hivyo, katika mfano wetu tunaongeza threat kwa Process entity, kwa hiyo tutaona haya katika threat creation box:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Imekamilika

Sasa model yako iliyokamilika inapaswa kuonekana hivi. Hivi ndivyo unavyounda threat model rahisi kwa kutumia OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft's Threat Modeling Tool ni tool ya bure inayopakuliwa kwa ajili ya software design analysis. Workflow yake huunda diagramu, hutambua threats, na kusaidia mitigation na validation kwa kutumia STRIDE approach.<sup>[[4]](#references)</sup>

## References

- [1] [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Threat Modeling - The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Misingi ya usalama - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Kuanza kutumia Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Threat Modeling kwa Drivers - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [Threat Modeling ya PASTA: Hatua 7 Zimeelezwa](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Hati ya Methodology ya Trike v1](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Threat Modeling: Muhtasari wa Methods Zinazopatikana](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
