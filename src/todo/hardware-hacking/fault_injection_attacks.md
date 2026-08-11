# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection, bir cihaz çalışırken onu kasıtlı olarak bozarak yanlış bir hesaplama yapmasını sağlar. Kullanışlı bir fault; bir talimatı atlayabilir, verileri bozabilir, bir security check'i atlayabilir veya gizli bilgilerin türetilebileceği hatalı cryptographic output üretebilir.<sup>[[1]](#references)</sup>

Yaygın teknikler supply voltage veya clock sinyalini manipüle eder, electromagnetic interference enjekte eder ya da optical veya laser stimulation kullanır.<sup>[[1]](#references)</sup> Hassasiyetleri ve müdahale düzeyleri farklıdır; ancak başarılı testler genellikle tekrarlanabilir bir trigger ile timing, pulse width ve intensity üzerinde sistematik taramalar gerektirir. Kararlı bir baseline ile başlayın, reset'leri ve hatalı output'ları ayrı ayrı kaydedin ve her seferinde yalnızca bir parametreyi değiştirin.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Kasıtlı Electromagnetic Interference'a Dayalı Non-invasive Trigger-free Fault Injection Method](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - Capture Hardware Overview and Comparison](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
