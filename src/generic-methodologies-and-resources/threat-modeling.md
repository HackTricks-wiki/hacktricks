# Threat Modeling

HackTricks'in kapsamlı Threat Modeling rehberine hoş geldiniz! Bir sistemdeki olası zayıflıkları belirlediğimiz, anladığımız ve bunlara karşı strateji geliştirdiğimiz bu kritik cybersecurity alanını keşfedin. Bu bölüm, gerçek dünya örnekleri, faydalı yazılımlar ve kolay anlaşılır açıklamalarla hazırlanmış adım adım bir rehberdir. Cybersecurity savunmalarını güçlendirmek isteyen hem yeni başlayanlar hem de deneyimli uygulayıcılar için uygundur.

### Yaygın Kullanım Senaryoları

1. **Software Development**: Secure Software Development Life Cycle (SSDLC) kapsamında Threat Modeling, geliştirmenin erken aşamalarında **olası zayıflık kaynaklarının belirlenmesine** yardımcı olur.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES), doğru uygulama için Threat Modeling'i gerekli kabul eder ve business asset'lerin, business process'lerin, threat community'lerin ve bunların yeteneklerinin belgelenmesini ister.<sup>[[2]](#references)</sup>

### Threat Model Kısaca

Bir threat model genellikle planlanan bir architecture'ın veya mevcut bir application'ın diagram, image ya da başka bir görsel gösterimi şeklinde sunulur. Data-flow diagram'ları (DFD'ler), bir sistemi ve etkileşimlerini modellemek için yaygın bir yöntemdir; Threat Modeling ise buna security odaklı bir analiz ekler.<sup>[[1]](#references)</sup>

Microsoft's Threat Modeling Tool'da kırmızı kesikli çizgiler trust boundary'leri gösterir; diğer araçlar farklı görsel kurallar kullanabilir.<sup>[[4]](#references)</sup> Risk tanımlamasını kolaylaştırmak için ekipler CIA (Confidentiality, Integrity, Availability) üçlüsünü veya STRIDE threat kategorilerini kullanabilir; ancak uygun methodology projenin bağlamına ve gereksinimlerine bağlıdır.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### CIA Triad

CIA Triad, Confidentiality, Integrity ve Availability kavramlarını ifade eden, yaygın olarak tanınan bir information-security modelidir. Bu özellikler, data ve system'ler için security hedeflerini tanımlamak amacıyla yaygın şekilde kullanılır.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Data veya system'e unauthorized kişilerin erişmemesini sağlamak. Bu, data breach'lerini önlemek için uygun access control'leri, encryption'ı ve diğer önlemleri gerektiren security'nin temel bir unsurudur.
2. **Integrity**: Data'nın yaşam döngüsü boyunca doğruluğu, tutarlılığı ve güvenilirliği. Bu ilke, data'nın unauthorized taraflarca değiştirilmemesini veya manipüle edilmemesini sağlar. Genellikle checksum'ları, hashing'i ve diğer data doğrulama yöntemlerini içerir.
3. **Availability**: Data ve service'lerin gerektiğinde authorized kullanıcılara erişilebilir olmasını sağlar. Bu genellikle, kesintiler karşısında bile system'lerin çalışmaya devam etmesi için redundancy, fault tolerance ve high-availability configuration'larını içerir.

### Threat Modeling Methodologies

1. **STRIDE**: Microsoft's STRIDE yaklaşımı, software threat'lerini **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service ve Elevation of Privilege** olarak kategorilere ayırır. Bu kategoriler, analistlerin bir design'daki her vulnerable noktada olası threat'leri belirlemesine yardımcı olur.<sup>[[5]](#references)</sup>
2. **DREAD**: Bu Microsoft assessment yaklaşımı, threat'leri **Damage, Reproducibility, Exploitability, Affected users ve Discoverability** kullanarak puanlar. Ortaya çıkan puan, mitigation için threat'lere öncelik verilmesine yardımcı olabilir.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Bu, objectives, technical scope, application decomposition, threat analysis, vulnerability and weakness analysis, attack modeling ve risk/impact analysis aşamalarını kapsayan, yedi aşamalı ve **risk-centric** bir methodology'dir.<sup>[[8]](#references)</sup>
4. **Trike**: Bu security-audit framework'ü, Threat Modeling'e **risk-management** ve defensive bir bakış açısıyla yaklaşır.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Bu method, application ve operational görünümler için ölçeklenebilir ve kullanılabilir threat model'leri vurgular ve development ile DevOps lifecycle'larına entegre olabilir.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Carnegie Mellon's Software Engineering Institute'ının CERT Division'ı tarafından oluşturulan OCTAVE, yalnızca technology yerine organizational risk'e odaklanan, risk tabanlı strategic bir assessment ve planning method'udur.<sup>[[10]](#references)</sup>

## Tools

Threat model'lerin oluşturulmasına ve yönetilmesine **yardımcı** olabilecek çeşitli tool ve software çözümleri mevcuttur. Değerlendirebileceğiniz birkaç seçenek aşağıda verilmiştir.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite, security profesyonelleri için attack-surface mapping, endpoint discovery ve web-application analysis destekleyen cross-platform bir web crawler'dır.<sup>[[6]](#references)</sup>

**Kullanım**

1. Bir URL seçin ve Crawl işlemini başlatın

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Graph'ı görüntüleyin

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon; diagram çizmek, threat önermek ve mitigation'ları kaydetmek için kullanılan ücretsiz, open-source, cross-platform bir threat-modeling application'ıdır. Web ve desktop application'ları olarak kullanılabilir.<sup>[[7]](#references)</sup>

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

Size ilham vermesi için SpiderSuite Crawler gibi tool'lar kullanabilirsiniz; temel bir model şu şekilde görünebilir

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Entity'ler hakkında kısaca açıklama:

- Process (Webserver veya web functionality gibi entity'nin kendisi)
- Actor (Website Visitor, User veya Administrator gibi bir kişi)
- Data Flow Line (Interaction göstergesi)
- Trust Boundary (Farklı network segment'leri veya scope'lar.)
- Store (Database gibi data'nın depolandığı yerler)

5. Bir Threat oluşturun (Adım 1)

Öncelikle threat eklemek istediğiniz layer'ı seçmeniz gerekir

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Şimdi threat'i oluşturabilirsiniz

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Actor Threats ve Process Threats arasında fark olduğunu unutmayın. Bir Actor'a threat eklerseniz yalnızca "Spoofing" ve "Repudiation" seçeneklerini seçebilirsiniz. Ancak örneğimizde bir Process entity'sine threat eklediğimiz için threat creation box'ında şunu göreceğiz:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Tamamlandı

Artık tamamladığınız model şu şekilde görünmelidir. OWASP Threat Dragon ile basit bir threat model'i bu şekilde oluşturabilirsiniz.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft's Threat Modeling Tool, software design analysis için ücretsiz olarak indirilebilen bir tool'dur. Workflow'u bir diagram oluşturur, threat'leri belirler ve STRIDE yaklaşımını kullanarak mitigation ile validation işlemlerini destekler.<sup>[[4]](#references)</sup>

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
