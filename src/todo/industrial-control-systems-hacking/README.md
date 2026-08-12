# Industrial Control Systems Hacking

{{#include ../../banners/hacktricks-training.md}}

## Bu Bölüm Hakkında

Bu bölüm, endüstriyel kontrol sistemi (ICS) bileşenlerini, mimarilerini, protokollerini ve güvenlik değerlendirme yöntemlerini tanıtır. ICS, fiziksel süreçleri izleyen veya bu süreçlerde değişikliklere neden olan programlanabilir sistem ve cihazlardan oluşan daha geniş operasyonel teknoloji (OT) alanının bir parçasıdır. Yaygın örnekler arasında denetleyici kontrol ve veri toplama (SCADA) sistemleri, dağıtık kontrol sistemleri (DCS'ler) ve programlanabilir mantık denetleyicileri (PLC'ler) bulunur.<sup>[[1]](#references)</sup>

Bu ortamlardaki güvenlik çalışmaları; süreç güvenliği, güvenilirlik, kullanılabilirlik, deterministik çalışma ve ekipman yaşam döngüleri gibi geleneksel IT'den farklı gereksinimleri dikkate almalıdır. Teknik olarak geçerli bir güvenlik kontrolü, fiziksel süreci kesintiye uğratıyorsa yine de uygun olmayabilir; bu nedenle test ve iyileştirme çalışmaları sistem sahibi ve operasyon personeliyle koordineli şekilde yürütülmelidir.<sup>[[1]](#references)</sup>

Sistemin ele geçirilmesi veya kazara kesintiye uğraması üretimi durdurabilir, ekipmana zarar verebilir, tehlikeli maddelerin açığa çıkmasına, çevrenin zarar görmesine veya yaralanma ve can kaybına neden olabilir. Bu potansiyel fiziksel etki nedeniyle, aktif testlerden önce kontrol edilen sürecin ve güvenli çalışma sınırlarının anlaşılması gerekir.<sup>[[1]](#references)</sup>

Birçok OT kurulumu, ekipmanların uzun hizmet ömrüne sahip olması ve değişikliklerin operasyonel ve güvenlik testleri gerektirmesi nedeniyle eski işletim sistemlerini, uygulamaları ve protokolleri kullanmaya devam eder. Bazı protokoller modern kimlik doğrulama veya şifreleme olmadan tasarlanmıştır ve patching, vendor desteği veya bakım aralıkları nedeniyle kısıtlanabilir; doğrudan yükseltmelerin uygulanabilir olmadığı durumlarda segmentation, access control ve monitoring ile telafi sağlayın.<sup>[[1]](#references)</sup>

## Değerlendirme Öncelikleri

Kontrol edilen süreci, sistem sınırlarını, network topolojisini, varlıkları, veri akışlarını, trust ilişkilerini ve harici bağlantıları anlayarak başlayın. Benzer cihaz türleri farklı tesislerde farklı işlevlere hizmet edebilir; bu nedenle bir kurulumun mimarisinin veya etki modelinin başka bir kurulum için geçerli olduğunu varsaymaktan kaçının.<sup>[[1]](#references)</sup>

Mümkün olduğunda passive discovery ve mevcut mühendislik dokümantasyonunu tercih edin. Her türlü active scanning veya exploitation, güvenlik kısıtlarını, bakım aralıklarını, kurtarma prosedürlerini ve durdurma koşullarını tanımlayan onaylı bir test planını izlemelidir. Bulgular hem cybersecurity etkisi hem de fiziksel süreç üzerindeki potansiyel etkiler açısından değerlendirilmelidir.<sup>[[1]](#references)</sup>

Aynı mimari bilgisi asset inventory, network segmentation, monitoring, incident response ve risk tabanlı vulnerability management gibi savunma faaliyetlerini de destekler.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Operasyonel Teknoloji (OT) Güvenliği Kılavuzu](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
