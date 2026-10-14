# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection—donanım güvenliği çalışmalarında genellikle **glitching** olarak adlandırılır—cihaz çalışırken, hatalı hesaplama yapmasını sağlamak amacıyla cihaza kasıtlı olarak müdahale eder. Yararlı bir hata; bir talimatın atlanmasına, verilerin bozulmasına, güvenlik denetiminin aşılmasına veya gizli bilgilerin çıkarılabileceği hatalı kriptografik çıktılar üretilmesine neden olabilir.<sup>[[1]](#references)</sup>

Yaygın teknikler, besleme gerilimini veya saat sinyalini değiştirir, elektromanyetik parazit uygular ya da optik veya lazer uyarımı kullanır.<sup>[[1]](#references)</sup> Hassasiyetleri ve müdahale düzeyleri farklı olsa da başarılı testler genellikle tekrarlanabilir bir tetikleyici ve zamanlama, darbe genişliği ve yoğunluk üzerinde sistematik taramalar gerektirir. Kararlı bir başlangıç durumu oluşturun, sıfırlamaları ve bozuk çıktıları ayrı ayrı kaydedin ve her seferinde tek bir parametreyi değiştirin.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Kasıtlı Elektromanyetik Girişime Dayalı, Tetikleyicisiz Hata Enjeksiyonu Yöntemi](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - Yakalama Donanımına Genel Bakış ve Karşılaştırma](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
