# Industrial Control Systems Hacking

{{#include ../../banners/hacktricks-training.md}}

## Bu Bölüm Hakkında

Bu bölümde industrial control system (ICS) bileşenleri, mimarileri, protokolleri ve security assessment yöntemleri tanıtılmaktadır. ICS, fiziksel süreçleri izleyen veya bu süreçlerde değişikliklere neden olan programlanabilir sistemleri ve cihazları kapsayan daha geniş operational technology (OT) alanının bir parçasıdır. Yaygın örnekler arasında supervisory control and data acquisition (SCADA) sistemleri, distributed control systems (DCSs) ve programmable logic controllers (PLCs) bulunur.<sup>[[1]](#references)</sup>

Bu ortamlardaki security çalışmaları; süreç güvenliği, güvenilirlik, kullanılabilirlik, deterministik çalışma ve ekipman yaşam döngüleri gibi geleneksel IT'den farklı gereksinimleri dikkate almalıdır. Teknik olarak geçerli bir security control, fiziksel süreci aksatıyorsa yine de uygun olmayabilir; bu nedenle test ve remediation işlemleri sistem sahibi ve operasyon personeliyle koordineli şekilde yürütülmelidir.<sup>[[1]](#references)</sup>

## Assessment Öncelikleri

Kontrol edilen süreci, sistem sınırlarını, network topology'sini, varlıkları, data flow'larını, trust relationship'lerini ve harici bağlantıları anlayarak başlayın. Benzer cihaz türleri farklı tesislerde farklı işlevler üstlenebilir; bu nedenle bir deployment'ın mimarisinin veya impact model'inin başka bir deployment için geçerli olduğunu varsaymaktan kaçının.<sup>[[1]](#references)</sup>

Mümkün olduğunda passive discovery'yi ve mevcut engineering dokümantasyonunu tercih edin. Her türlü active scanning veya exploitation işlemi; güvenlik kısıtlarını, maintenance window'larını, recovery prosedürlerini ve durdurma koşullarını tanımlayan onaylı bir test planını izlemelidir. Bulgular hem cybersecurity impact hem de fiziksel süreç üzerindeki olası etkiler açısından değerlendirilmelidir.<sup>[[1]](#references)</sup>

Aynı mimari bilgisi; asset inventory, network segmentation, monitoring, incident response ve risk-based vulnerability management gibi defensive faaliyetleri de destekler.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Operational Technology (OT) Security Rehberi](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
