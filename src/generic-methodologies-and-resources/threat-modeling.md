# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

HackTricks'in Threat Modeling hakkındaki kapsamlı rehberine hoş geldiniz! Bir sistemdeki potansiyel güvenlik açıklarını belirlediğimiz, anladığımız ve bunlara karşı strateji geliştirdiğimiz bu kritik cybersecurity alanını keşfetmeye başlayın. Bu bölüm, gerçek dünya örnekleri, faydalı yazılımlar ve kolay anlaşılır açıklamalarla hazırlanmış adım adım bir rehberdir. Hem yeni başlayanlar hem de cybersecurity savunmalarını güçlendirmek isteyen deneyimli uygulayıcılar için idealdir.

### Yaygın Kullanım Senaryoları

1. **Software Development**: Secure Software Development Life Cycle'ın (SSDLC) bir parçası olarak threat modeling, geliştirmenin erken aşamalarında **güvenlik açıklarının potansiyel kaynaklarını belirlemeye** yardımcı olur.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES), doğru uygulama için threat modeling'i gerekli kabul eder ve business assets, business processes, threat communities ve bunların yeteneklerinin belgelenmesini ister.<sup>[[2]](#references)</sup>

### Kısaca Threat Model

Threat model genellikle planlanan bir mimarinin veya mevcut bir uygulamanın diyagramı, görseli ya da başka bir görsel gösterimi olarak sunulur. Data-flow diagrams (DFDs), bir sistemi ve etkileşimlerini modellemenin yaygın bir yoludur; threat modeling ise security odaklı bir analiz ekler.<sup>[[1]](#references)</sup>

Microsoft's Threat Modeling Tool'da kırmızı noktalı çizgiler trust boundaries'i gösterir; diğer araçlar farklı görsel kurallar kullanabilir.<sup>[[4]](#references)</sup> Risk tanımlamasını kolaylaştırmak için ekipler CIA (Confidentiality, Integrity, Availability) triad'ını veya STRIDE threat categories'lerini kullanabilir; ancak uygun methodology, projenin bağlamına ve gereksinimlerine bağlıdır.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### CIA Triad

CIA Triad, Confidentiality, Integrity ve Availability ifadelerini temsil eden, yaygın olarak kabul görmüş bir information-security modelidir. Bu özellikler genellikle data ve sistemler için security hedeflerini tanımlamak amacıyla kullanılır.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Data veya sisteme unauthorized kişilerin erişmemesini sağlamak. Bu, data breach'lerini önlemek için uygun access controls, encryption ve diğer önlemleri gerektiren, security'nin temel bir unsurudur.
2. **Integrity**: Data'nın yaşam döngüsü boyunca doğruluğu, tutarlılığı ve güvenilirliği. Bu ilke, data'nın unauthorized taraflarca değiştirilmemesini veya manipüle edilmemesini sağlar. Genellikle checksums, hashing ve diğer data verification yöntemlerini içerir.
3. **Availability**: Data ve servislerin gerektiğinde authorized kullanıcılar tarafından erişilebilir olmasını sağlar. Bu genellikle kesintiler karşısında dahi sistemlerin çalışmasını sürdürmek için redundancy, fault tolerance ve high-availability yapılandırmalarını içerir.

### Threat Modeling Methodologies

1. **STRIDE**: Microsoft's STRIDE yaklaşımı software threats'leri **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service ve Elevation of Privilege** olarak kategorize eder. Bu kategoriler, analistlerin bir tasarımdaki her vulnerable noktada olası threat'leri belirlemesine yardımcı olur.<sup>[[5]](#references)</sup>
2. **DREAD**: Bu Microsoft assessment yaklaşımı threat'leri **Damage, Reproducibility, Exploitability, Affected users ve Discoverability** kullanarak puanlar. Ortaya çıkan puan, mitigation için threat'lere öncelik verilmesine yardımcı olabilir.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Bu, objectives, technical scope, application decomposition, threat analysis, vulnerability and weakness analysis, attack modeling ve risk/impact analysis'i kapsayan yedi aşamalı, **risk-centric** bir methodology'dir.<sup>[[8]](#references)</sup>
4. **Trike**: Bu security-audit framework'ü threat modeling'e **risk-management** ve defensive perspektiften yaklaşır.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Bu method, application ve operational görünümler için ölçeklenebilir ve kullanılabilir threat model'lerini vurgular ve development ile DevOps lifecycle'larına entegre olabilir.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Carnegie Mellon's Software Engineering Institute'ının CERT Division'ı tarafından oluşturulan OCTAVE, yalnızca technology yerine organizational risk'e odaklanan, risk-based strategic assessment ve planning method'udur.<sup>[[10]](#references)</sup>

## Araçlar

Threat model'lerinin oluşturulmasına ve yönetilmesine **yardımcı** olabilecek çeşitli araçlar ve software çözümleri mevcuttur. Değerlendirebileceğiniz birkaç seçenek aşağıda yer almaktadır.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite, security profesyonelleri için attack-surface mapping, endpoint discovery ve web-application analysis desteği sunan cross-platform bir web crawler'dır.<sup>[[6]](#references)</sup>

**Kullanım**

1. Bir URL seçin ve Crawl işlemini başlatın

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Graph'ı görüntüleyin

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon; diyagram çizmek, threat'ler önermek ve mitigation'ları kaydetmek için kullanılan ücretsiz, open-source, cross-platform bir threat-modeling application'dır. Web ve desktop application olarak kullanılabilir.<sup>[[7]](#references)</sup>

**Kullanım**

1. New Project oluşturun

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Bazen şu şekilde görünebilir:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. New Project'i başlatın

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. New Project'i kaydedin

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Model'inizi oluşturun

İlham almak için SpiderSuite Crawler gibi araçları kullanabilirsiniz; temel bir model aşağıdakine benzer görünebilir.

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Entity'ler hakkında kısaca açıklama:

- Process (Webserver veya web functionality gibi entity'nin kendisi)
- Actor (Website Visitor, User veya Administrator gibi bir kişi)
- Data Flow Line (Interaction göstergesi)
- Trust Boundary (Farklı network segment'leri veya scope'lar.)
- Store (Database gibi data'nın depolandığı yerler)

5. Threat oluşturun (Adım 1)

Öncelikle threat eklemek istediğiniz layer'ı seçmelisiniz.

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Şimdi threat'ü oluşturabilirsiniz.

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Actor Threats ve Process Threats arasında fark olduğunu unutmayın. Bir Actor'a threat eklediğinizde yalnızca "Spoofing" ve "Repudiation" seçeneklerini seçebilirsiniz. Ancak örneğimizde bir Process entity'sine threat eklediğimiz için threat creation box'ında şunları görürüz:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Tamamlandı

Artık tamamlanmış model'iniz aşağıdakine benzer görünmelidir. OWASP Threat Dragon ile basit bir threat model'i bu şekilde oluşturabilirsiniz.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft's Threat Modeling Tool, software design analysis için ücretsiz olarak indirilebilen bir araçtır. Workflow'u bir diyagram oluşturur, threat'leri belirler ve STRIDE yaklaşımını kullanarak mitigation ve validation desteği sunar.<sup>[[4]](#references)</sup>

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
