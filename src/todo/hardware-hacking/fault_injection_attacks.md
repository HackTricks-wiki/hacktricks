# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection - hardware-security çalışmalarında sıklıkla **glitching** olarak adlandırılır - bir cihaz çalışırken onu kasıtlı olarak bozarak yanlış bir hesaplama yapmasını sağlar. Kullanışlı bir fault bir instruction'ı atlayabilir, verileri bozabilir, bir security check'i bypass edebilir veya secret bilgilerin elde edilebileceği hatalı cryptographic output üretebilir.<sup>[[1]](#references)</sup>

Yaygın teknikler supply voltage veya clock sinyallerini manipüle eder, electromagnetic interference enjekte eder ya da optical veya laser stimulation kullanır.<sup>[[1]](#references)</sup> Hassasiyetleri ve müdahale düzeyleri farklıdır; ancak başarılı testing genellikle tekrarlanabilir bir trigger ile timing, pulse width ve intensity değerleri üzerinde sistematik sweep'ler gerektirir. Kararlı bir baseline ile başlayın, reset'leri ve malformed output'ları ayrı ayrı kaydedin ve her seferinde tek bir parametreyi değiştirin.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Kasıtlı Electromagnetic Interference'e Dayalı Non-invasive Trigger-free Fault Injection Method](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - Capture Hardware Genel Bakışı ve Karşılaştırması](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
