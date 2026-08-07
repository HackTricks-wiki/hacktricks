# Uundaji wa Muundo wa Vitisho

{{#include ../banners/hacktricks-training.md}}

## Uundaji wa Muundo wa Vitisho

Karibu kwenye mwongozo mpana wa HackTricks kuhusu Uundaji wa Muundo wa Vitisho! Anza kuchunguza kipengele hiki muhimu cha cybersecurity, ambapo tunatambua, kuelewa na kupanga mikakati dhidi ya vulnerabilities zinazoweza kutokea katika mfumo. Sehemu hii ni mwongozo wa hatua kwa hatua uliojaa mifano ya ulimwengu halisi, software muhimu na maelezo yanayoeleweka kwa urahisi. Unafaa kwa wanaoanza na wataalamu wenye uzoefu wanaotaka kuimarisha ulinzi wao wa cybersecurity.

### Matukio Yanayotumika Mara kwa Mara

1. **Utengenezaji wa Software**: Kama sehemu ya Secure Software Development Life Cycle (SSDLC), threat modeling husaidia katika **kutambua vyanzo vinavyoweza kusababisha vulnerabilities** katika hatua za awali za utengenezaji.
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) framework inahitaji **threat modeling ili kuelewa vulnerabilities za mfumo** kabla ya kutekeleza test.

### Threat Model kwa Ufupi

Threat Model kwa kawaida huwakilishwa kwa mchoro, picha au aina nyingine ya illustration inayoonyesha architecture iliyopangwa au build iliyopo ya application. Inafanana na **data flow diagram**, lakini tofauti kuu iko katika muundo wake unaolenga usalama.

Threat models mara nyingi huwa na elements zilizowekwa alama nyekundu, zinazoashiria vulnerabilities, risks au barriers zinazoweza kutokea. Ili kurahisisha mchakato wa kutambua risks, hutumika triad ya CIA (Confidentiality, Integrity, Availability), ambayo huunda msingi wa methodologies nyingi za threat modeling, STRIDE ikiwa mojawapo ya zinazotumika zaidi. Hata hivyo, methodology iliyochaguliwa inaweza kutofautiana kulingana na muktadha na mahitaji mahususi.

### Triad ya CIA

Triad ya CIA ni model inayotambulika sana katika uwanja wa information security, ikimaanisha Confidentiality, Integrity na Availability. Nguzo hizi tatu huunda msingi ambao security measures na policies nyingi hujengwa juu yake, zikiwemo methodologies za threat modeling.

1. **Confidentiality**: Kuhakikisha kwamba data au mfumo haupatikani na watu wasioidhinishwa. Hiki ni kipengele cha msingi cha security, kinachohitaji access controls zinazofaa, encryption na measures nyingine za kuzuia data breaches.
2. **Integrity**: Usahihi, consistency na uaminifu wa data katika lifecycle yake. Kanuni hii huhakikisha kwamba data haibadilishwi au kuchezewa na parties zisizoidhinishwa. Mara nyingi huhusisha checksums, hashing na mbinu nyingine za kuthibitisha data.
3. **Availability**: Kuhakikisha kwamba data na services zinapatikana kwa users walioidhinishwa zinapohitajika. Mara nyingi hii huhusisha redundancy, fault tolerance na configurations zenye high availability ili kuweka systems zikiendelea kufanya kazi hata zinapokumbwa na disruptions.

### Methodologies za Threat Modeling

1. **STRIDE**: Iliyotengenezwa na Microsoft, STRIDE ni kifupi cha **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service na Elevation of Privilege**. Kila category inawakilisha aina ya threat, na methodology hii hutumiwa kwa kawaida katika design phase ya program au system ili kutambua threats zinazoweza kutokea.
2. **DREAD**: Hii ni methodology nyingine kutoka Microsoft inayotumiwa kwa risk assessment ya threats zilizotambuliwa. DREAD inamaanisha **Damage potential, Reproducibility, Exploitability, Affected users na Discoverability**. Kila moja ya factors hizi hupewa score, na matokeo hutumiwa kuweka kipaumbele cha threats zilizotambuliwa.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Hii ni methodology ya hatua saba, inayolenga **risk**. Inajumuisha kufafanua na kutambua security objectives, kuunda technical scope, application decomposition, threat analysis, vulnerability analysis na risk/triage assessment.
4. **Trike**: Hii ni risk-based methodology inayolenga kulinda assets. Huanzia katika mtazamo wa **risk management** na huchunguza threats na vulnerabilities katika muktadha huo.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Approach hii inalenga kuwa rahisi zaidi kufikiwa na huunganishwa katika Agile development environments. Huchanganya elements kutoka methodologies nyingine na kulenga **visual representations za threats**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Framework hii iliyotengenezwa na CERT Coordination Center inalenga **organizational risk assessment badala ya systems au software mahususi**.

## Tools

Kuna tools na software solutions kadhaa zinazopatikana ambazo zinaweza **kusaidia** katika kuunda na kusimamia threat models. Hapa kuna baadhi unazoweza kuzingatia.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Ni GUI web spider/crawler ya advanced, ya cross-platform na yenye features nyingi kwa wataalamu wa cybersecurity. Spider Suite inaweza kutumika kwa attack surface mapping na analysis.

**Matumizi**

1. Chagua URL na Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Tazama Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Ni open-source project kutoka OWASP. Threat Dragon ni web na desktop application inayojumuisha system diagramming pamoja na rule engine ya kutengeneza threats/mitigations kiotomatiki.

**Matumizi**

1. Unda New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Wakati mwingine inaweza kuonekana hivi:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Launch New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Save The New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Unda model yako

Unaweza kutumia tools kama SpiderSuite Crawler kupata inspiration; model ya msingi inaweza kuonekana hivi

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Haya ni maelezo mafupi kuhusu entities:

- Process (Entity yenyewe kama Webserver au web functionality)
- Actor (Mtu kama Website Visitor, User au Administrator)
- Data Flow Line (Indicator ya Interaction)
- Trust Boundary (Network segments au scopes tofauti.)
- Store (Vitu ambavyo data huhifadhiwa, kama Databases)

5. Unda Threat (Hatua ya 1)

Kwanza lazima uchague layer ambayo ungependa kuongeza threat

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Sasa unaweza kuunda threat

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Kumbuka kwamba kuna tofauti kati ya Actor Threats na Process Threats. Ukiongeza threat kwenye Actor, utaweza kuchagua tu "Spoofing" na "Repudiation. Hata hivyo, katika mfano wetu tunaongeza threat kwenye Process entity, kwa hiyo tutaona hivi katika threat creation box:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Umemaliza

Sasa model yako iliyokamilika inapaswa kuonekana hivi. Hivi ndivyo unavyounda threat model rahisi kwa kutumia OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Hii ni tool ya bure kutoka Microsoft inayosaidia kutafuta threats katika design phase ya software projects. Inatumia methodology ya STRIDE na inafaa hasa kwa wanaotengeneza kwenye Microsoft stack.

{{#include ../banners/hacktricks-training.md}}
