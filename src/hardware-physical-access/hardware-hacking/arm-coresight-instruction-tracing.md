# SWO üzerinden ARM CoreSight Instruction Tracing

{{#include ../../banners/hacktricks-training.md}}

Erişilebilir bir [SWD/JTAG debug port](jtag.md), firmware enstrümantasyonu olmadan canlı Cortex-M execution trace'i etkinleştirmek için kullanılabilir. Bunun için ETM ve TPIU içeren bir MCU, dışarı çıkarılmış bir SWO hattı, decode işlemi için firmware'in tam bir kopyası ve seçilen SWO bit hızına yetecek kadar hızlı bir logic analyzer gerekir. [Güç veya EM side-channel ölçümlerinden](side_channel_analysis.md) farklı olarak ETM bir debug trace'tir; ikisini birlikte kaydetmek, gözlemlenen leak'i yürütülen kodla hizalayabilir. Aynı hizalama, [fault injection](fault_injection_attacks.md) zamanlamasına da yardımcı olabilir.<sup>[[1]](#references)</sup>

ETM, instruction byte'ları yerine sıkıştırılmış control-flow event'leri üretir. Bir decoder, eşleşen firmware image'ını kullanarak yürütmeyi yeniden oluşturur. ITM yazılım enstrümantasyonu taşırken TPIU, trace kaynaklarını çerçeveler ve seri kablo çıkışını sağlar. Herhangi bir register değerini uygulamadan önce hedefin CoreSight bileşenlerini ve pin multiplexing ayarlarını reference manual'dan kontrol edin: aşağıdaki örnek STM32F401 içindir, tüm Cortex-M yapılandırmaları için geçerli değildir.<sup>[[1]](#references)</sup>

## Trace çıkışını bulma

STM32F401'de asenkron SWO, PB3'ü kullanır. İncelenen kontrolcüde PB3, erişilebilir bir probe noktası sağlayan R15 direncine bağlıydı. Paket veya net görünmüyorsa, SWD memory write'ları üzerinden değiştirerek aday SWO destekli pini geçici olarak GPIO olarak yapılandırın. Eşleşen waveform'u bulmak için kart üzerindeki noktaları probla kontrol edin, ardından trace pin yapılandırmasını geri yükleyin. Analyzer'ı ortak bir ground ve uyumlu bir logic voltage ile bağlayın.<sup>[[1]](#references)</sup>

## OpenOCD ile TPIU ve ETM'yi etkinleştirme

Aşağıdaki komutlar, uygun adapter ve `target/stm32f4x.cfg` seçildikten sonra bir OpenOCD yapılandırmasına eklenmelidir. `setbits`, control register'lardaki ilgisiz bitleri korurken `mww` tüm word'ü üzerine yazar. Önce TPIU asenkron trace'i yönlendirir; ardından ETM'nin kilidi açılır, programlama modunda yapılandırılır, trace source ID `1` atanır ve başlatılır. Bu değerler yazarın çalışan STM32F401 yapılandırmasına dayanır; bu nedenle hedefin register map'ine ve clock tree'sine göre uyarlayın.<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>STM32F401 OpenOCD trace-register yapılandırması</summary>

```tcl
proc setbits {addr mask} {
    mem2array value 32 $addr 1
    set value(0) [expr {$value(0) | $mask}]
    array2mem value 32 $addr 1
}
init
reset halt
setbits 0xe0042004 0x20       ;# DBGMCU_CR: trace I/O, async SWO
setbits 0xe000edfc 0x1000000  ;# DEMCR: TRCENA
mww 0xe0040004 1              ;# TPIU_CPSR: port size
mww 0xe0040010 3              ;# TPIU_ACPR: 16 MHz / (3 + 1) = 4 Mbaud
mww 0xe00400f0 2              ;# TPIU_SPPR: async UART framing
mww 0xe0040304 0x102          ;# TPIU_FFCR: formatter
mww 0xe0041fb0 0xC5ACCE55     ;# ETM_LAR: unlock
mww 0xe0041000 0x00201d0e     ;# ETM_CR: programming mode
mww 0xe0041200 1              ;# ETM_TRACEIDR: source ID 1
mww 0xe0041008 0x0000406F     ;# ETM_TER: trigger event
mww 0xe0041020 0x0000006F     ;# ETM_TEE: trace-enable event
mww 0xe0041024 0x00000001     ;# ETM_TSSR: start trace
mww 0xe0041000 0x0000191E     ;# ETM_CR: leave programming mode
```

</details>

SWO hızı `HCLK / (TPIU_ACPR + 1)` değeridir. 16 MHz HCLK ve `ACPR=3` ile 4 Mbaud hızında yakalama yapın. PulseView'da ETM decoder'ı SWO analyzer kanalındaki UART decoder'ın üzerine yerleştirin, UART'ı gerçek wire hızına ayarlayın ve yukarıda yapılandırılan ETM source ID'yi kullanın. Örnekte 24 MHz örnekleme (bit başına altı örnek), düşen kenar tetiklemesi ve %25 pre-trigger yakalama kullanıldı. Yapılandırma tamamlandıktan sonra hedefi durdurun/sıfırlayın, yakalamayı başlatmaya hazır hale getirin ve ardından `resume` komutunu verin; yalnızca çözümlenmiş gibi görünen çıktıya güvenmek yerine ETM senkronizasyonunu ve firmware ile uyumlu, makul bir PC yolunu doğrulayın.<sup>[[1]](#references)</sup>

## Saat ve pin-mux değişikliklerinden kurtulma

Birbirinden bağımsız iki firmware eylemi, geçerli bir trace'i durdurabilir. PLL değişikliği HCLK'yi artırır ve `ACPR` sabit kaldığından SWO baud hızını da artırır; bu durumda UART katmanı hatalı baytları kurtarır ve ETM replay anlamsız hale gelir. [firmware analizinde](../firmware-analysis/) RCC/PLL kurulumunu inceleyin. STM32F401 örneğinde, Cortex-M image'ını `0x08000000` adresine yükleyin ve saat register'ı yazmalarının isimlerini görmek için SVD'sini Ghidra'ya aktarın. Saat başlatma işleminden *sonraki* iki baytlık bir Thumb talimatına hardware breakpoint koyun. Örnekte `bp 0x080001fa 2 hw` ve ardından `resume` komutu, PLL kurulumu tamamlandıktan sonra durur; duraklatılmış durumdayken `mww 0xe0040010 31` yeni divider'ı ayarlar. Yeni UART hızını hesaplayıp ayarlayın, yakalamayı başlatmaya hazır hale getirin ve ardından tekrar `resume` komutunu verin. Bu, geçiş sonrasındaki yolu yakalar; kaçırılan geçişi geri getirmez.<sup>[[1]](#references)</sup>

Ayrıca firmware, SWO pad'ini başka bir peripheral'a yönlendirebilir. Örnekte GPIO alternate-function kurulumu PB3'ü I2C2 SDA olarak değiştirdi; bu nedenle hiçbir decoder ayarı o wire üzerindeki trace'i geri getiremezdi. Firmware'deki ilgili GPIO başlatma işlemini bulun ve ardından çağrı noktalarını aynı boyutta Thumb NOP'larla (her halfword için `0xBF00`) değiştirin ya da core'u durdurup SWD üzerinden trace ile uyumlu pin yapılandırmasını geri yükleyin. Her iki yöntem de yerinden edilen peripheral'ı devre dışı bırakabilir; çalışma anında yapılan bir geri yükleme de firmware tarafından tekrar üzerine yazılabilir. Pini çalışma anında geri yüklerken SWO divider'ını mevcut HCLK'ye göre ayarlayın.<sup>[[1]](#references)</sup>

## References

- [1] [Talimatları İzleme: ETM, ITM ve TPIU ile Canlı ARM Tracing](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: STM32F4 OpenOCD ETM/TPIU yapılandırması](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
