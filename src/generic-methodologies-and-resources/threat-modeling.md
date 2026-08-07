# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

## Threat Modeling

HackTricks'in Threat Modeling konusundaki kapsamlı rehberine hoş geldiniz! Bir sistemdeki olası zafiyetleri belirlediğimiz, anladığımız ve bunlara karşı strateji geliştirdiğimiz bu kritik cybersecurity alanını keşfetmeye başlayın. Bu bölüm, gerçek dünya örnekleri, faydalı yazılımlar ve kolay anlaşılır açıklamalarla hazırlanmış adım adım bir rehberdir. Cybersecurity savunmalarını güçlendirmek isteyen yeni başlayanlar ve deneyimli uygulayıcılar için uygundur.

### Yaygın Kullanım Senaryoları

1. **Software Development**: Secure Software Development Life Cycle (SSDLC) sürecinin bir parçası olarak threat modeling, geliştirmenin erken aşamalarında **olası zafiyet kaynaklarının belirlenmesine** yardımcı olur.
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) framework'ü, testi gerçekleştirmeden önce **sistemin zafiyetlerini anlamak için threat modeling yapılmasını** gerektirir.

### Özetle Threat Model

Threat Model genellikle bir uygulamanın planlanan mimarisini veya mevcut yapısını gösteren bir diyagram, görsel ya da başka bir görsel anlatım biçiminde temsil edilir. **data flow diagram**'a benzer; ancak temel fark, security odaklı bir tasarıma sahip olmasıdır.

Threat model'lerde genellikle olası zafiyetleri, riskleri veya engelleri simgeleyen kırmızı işaretli öğeler bulunur. Risk tanımlama sürecini kolaylaştırmak için CIA (Confidentiality, Integrity, Availability) üçlüsü kullanılır. Bu üçlü, STRIDE'ın en yaygın kullanılanlardan biri olduğu birçok threat modeling metodolojisinin temelini oluşturur. Ancak seçilen metodoloji, özel bağlama ve gereksinimlere göre değişebilir.

### CIA Üçlüsü

CIA Üçlüsü, information security alanında yaygın olarak tanınan bir modeldir ve Confidentiality, Integrity ve Availability ifadelerini temsil eder. Bu üç temel unsur, threat modeling metodolojileri de dahil olmak üzere birçok security önleminin ve politikasının dayandığı temeli oluşturur.

1. **Confidentiality**: Verilere veya sisteme yetkisiz kişilerin erişmemesini sağlamak. Bu, data breach'lerini önlemek için uygun access control'leri, encryption'ı ve diğer önlemleri gerektiren security'nin temel unsurlarından biridir.
2. **Integrity**: Verilerin yaşam döngüsü boyunca doğruluğu, tutarlılığı ve güvenilirliği. Bu ilke, verilerin yetkisiz taraflarca değiştirilmemesini veya kurcalanmamasını sağlar. Genellikle checksum'ları, hashing'i ve diğer data doğrulama yöntemlerini içerir.
3. **Availability**: Verilerin ve servislerin gerektiğinde yetkili kullanıcılar tarafından erişilebilir olmasını sağlar. Bu genellikle kesintiler karşısında bile sistemlerin çalışmaya devam etmesi için redundancy, fault tolerance ve high-availability yapılandırmalarını içerir.

### Threat Modeling Methodolojileri

1. **STRIDE**: Microsoft tarafından geliştirilen STRIDE; **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service ve Elevation of Privilege** ifadelerinin baş harflerinden oluşur. Her kategori bir threat türünü temsil eder ve bu metodoloji, olası threat'leri belirlemek için genellikle bir programın veya sistemin tasarım aşamasında kullanılır.
2. **DREAD**: Bu, belirlenen threat'lerin risk değerlendirmesi için Microsoft tarafından geliştirilen başka bir metodolojidir. DREAD; **Damage potential, Reproducibility, Exploitability, Affected users ve Discoverability** ifadelerini temsil eder. Bu faktörlerin her biri puanlanır ve sonuç, belirlenen threat'lere öncelik vermek için kullanılır.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Bu, **risk-centric** bir yaklaşıma sahip yedi adımlı bir metodolojidir. Security hedeflerinin tanımlanmasını ve belirlenmesini, teknik kapsam oluşturulmasını, application decomposition'ı, threat analysis'i, vulnerability analysis'i ve risk/triage assessment'ı içerir.
4. **Trike**: Bu, asset'leri korumaya odaklanan risk tabanlı bir metodolojidir. **risk management** bakış açısıyla başlar ve threat'leri ve zafiyetleri bu bağlamda ele alır.
5. **VAST** (Visual, Agile, and Simple Threat modeling): Bu yaklaşım daha erişilebilir olmayı ve Agile development ortamlarına entegre olmayı amaçlar. Diğer metodolojilerden unsurları birleştirir ve **threat'lerin görsel temsillerine** odaklanır.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): CERT Coordination Center tarafından geliştirilen bu framework, **belirli sistemler veya yazılımlar yerine kurumsal risk değerlendirmesine** odaklanır.

## Tools

Threat model'lerin oluşturulmasına ve yönetilmesine **yardımcı olabilecek** çeşitli tool'lar ve software çözümleri mevcuttur. Değerlendirebileceğiniz birkaç seçenek aşağıda verilmiştir.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Cyber security profesyonelleri için geliştirilmiş, gelişmiş, cross-platform ve çok özellikli bir GUI web spider/crawler'ıdır. Spider Suite, attack surface mapping ve analysis için kullanılabilir.

**Kullanım**

1. Bir URL seçin ve Crawl işlemini başlatın

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Graph'ı görüntüleyin

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP tarafından geliştirilen open-source bir projedir. Threat Dragon, system diagramming özelliğinin yanı sıra threat'leri/mitigations'ları otomatik olarak oluşturmak için bir rule engine içeren hem web hem de desktop application'dır.

**Kullanım**

1. New Project oluşturun

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Bazen şöyle görünebilir:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. New Project'i başlatın

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. New Project'i kaydedin

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Model'inizi oluşturun

İlham almak için SpiderSuite Crawler gibi tool'lar kullanabilirsiniz. Temel bir model aşağıdakine benzer görünebilir:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Entity'ler hakkında kısa bir açıklama:

- Process (Webserver veya web functionality gibi entity'nin kendisi)
- Actor (Website Visitor, User veya Administrator gibi bir kişi)
- Data Flow Line (Interaction göstergesi)
- Trust Boundary (Farklı network segment'leri veya scope'lar.)
- Store (Database gibi verilerin depolandığı öğeler)

5. Threat oluşturma (1. Adım)

Öncelikle threat eklemek istediğiniz layer'ı seçmelisiniz

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Şimdi threat'i oluşturabilirsiniz

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Actor Threats ve Process Threats arasında fark olduğunu unutmayın. Bir Actor'a threat eklerseniz yalnızca "Spoofing" ve "Repudiation" seçeneklerini belirleyebilirsiniz. Ancak örneğimizde bir Process entity'sine threat eklediğimiz için threat creation kutusunda şunları görürüz:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Tamamlandı

Artık tamamlanmış modeliniz aşağıdakine benzer görünmelidir. OWASP Threat Dragon ile basit bir threat model'i bu şekilde oluşturabilirsiniz.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Bu, software project'lerinin design phase'inde threat'leri bulmaya yardımcı olan Microsoft'a ait ücretsiz bir tool'dur. STRIDE metodolojisini kullanır ve özellikle Microsoft stack'i üzerinde geliştirme yapanlar için uygundur.

{{#include ../banners/hacktricks-training.md}}
