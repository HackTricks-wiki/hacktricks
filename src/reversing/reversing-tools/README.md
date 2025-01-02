{{#include ../../banners/hacktricks-training.md}}

# Wasm Decompilation ve Wat Compilation Rehberi

**WebAssembly** alanında, **decompile** ve **compile** için araçlar geliştiriciler için gereklidir. Bu rehber, **Wasm (WebAssembly binary)** ve **Wat (WebAssembly text)** dosyalarını işlemek için bazı çevrimiçi kaynaklar ve yazılımlar tanıtmaktadır.

## Çevrimiçi Araçlar

- Wasm'ı Wat'a **decompile** etmek için [Wabt'nin wasm2wat demo](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) aracı kullanışlıdır.
- Wat'ı tekrar Wasm'a **compile** etmek için [Wabt'nin wat2wasm demo](https://webassembly.github.io/wabt/demo/wat2wasm/) amaca hizmet eder.
- Başka bir decompilation seçeneği [web-wasmdec](https://wwwg.github.io/web-wasmdec/) adresinde bulunabilir.

## Yazılım Çözümleri

- Daha sağlam bir çözüm için, [PNF Software tarafından JEB](https://www.pnfsoftware.com/jeb/demo) geniş özellikler sunmaktadır.
- Açık kaynak projesi [wasmdec](https://github.com/wwwg/wasmdec) de decompilation görevleri için mevcuttur.

# .Net Decompilation Kaynakları

.Net bileşenlerini decompile etmek için şu araçlar kullanılabilir:

- [ILSpy](https://github.com/icsharpcode/ILSpy), ayrıca [Visual Studio Code için bir eklenti](https://github.com/icsharpcode/ilspy-vscode) sunarak çapraz platform kullanımına olanak tanır.
- **Decompilation**, **modification** ve **recompilation** ile ilgili görevler için [dnSpy](https://github.com/0xd4d/dnSpy/releases) şiddetle tavsiye edilir. Bir metoda **sağ tıklamak** ve **Modify Method** seçeneğini seçmek, kod değişikliklerine olanak tanır.
- [JetBrains'in dotPeek](https://www.jetbrains.com/es-es/decompiler/) .Net bileşenlerini decompile etmek için başka bir alternatiftir.

## DNSpy ile Hata Ayıklama ve Günlükleme Geliştirme

### DNSpy Günlükleme

DNSpy kullanarak bir dosyaya bilgi kaydetmek için aşağıdaki .Net kod parçasını ekleyin:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### DNSpy Hata Ayıklama

DNSpy ile etkili bir hata ayıklama için, hata ayıklamayı engelleyebilecek optimizasyonların devre dışı bırakıldığından emin olmak için **Assembly attributes** ayarlarını ayarlamak üzere bir dizi adım önerilmektedir. Bu süreç, `DebuggableAttribute` ayarlarını değiştirmeyi, bileşeni yeniden derlemeyi ve değişiklikleri kaydetmeyi içerir.

Ayrıca, **IIS** tarafından çalıştırılan bir .Net uygulamasını hata ayıklamak için `iisreset /noforce` komutu IIS'i yeniden başlatır. DNSpy'ı hata ayıklama için IIS sürecine eklemek için, rehber **w3wp.exe** sürecini DNSpy içinde seçmeyi ve hata ayıklama oturumunu başlatmayı önerir.

Hata ayıklama sırasında yüklü modüllerin kapsamlı bir görünümü için, DNSpy'deki **Modules** penceresine erişmek ve ardından tüm modülleri açmak ve bileşenleri daha kolay gezinme ve hata ayıklama için sıralamak önerilir.

Bu rehber, WebAssembly ve .Net decompilation'ın özünü kapsar ve geliştiricilerin bu görevleri kolayca yönetmeleri için bir yol sunar.

## **Java Decompiler**

Java bytecode'u decompile etmek için bu araçlar oldukça yardımcı olabilir:

- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **DLL'leri Hata Ayıklama**

### IDA Kullanarak

- **Rundll32**, 64-bit ve 32-bit sürümleri için belirli yollar üzerinden yüklenir.
- **Windbg**, kütüphane yükleme/boşaltma sırasında askıya alma seçeneği etkinleştirilmiş olarak hata ayıklayıcı olarak seçilir.
- Çalıştırma parametreleri DLL yolu ve fonksiyon adını içerir. Bu yapılandırma, her DLL'nin yüklenmesi sırasında yürütmeyi durdurur.

### x64dbg/x32dbg Kullanarak

- IDA'ya benzer şekilde, **rundll32** komut satırı değişiklikleri ile DLL ve fonksiyonu belirtmek için yüklenir.
- DLL girişinde kırılma noktası ayarlamak için ayarlar, DLL giriş noktasında kırılma noktası ayarlamaya izin verecek şekilde ayarlanır.

### Görseller

- Yürütme durdurma noktaları ve yapılandırmalar ekran görüntüleri ile gösterilmektedir.

## **ARM & MIPS**

- Emülasyon için, [arm_now](https://github.com/nongiach/arm_now) yararlı bir kaynaktır.

## **Shellcodes**

### Hata Ayıklama Teknikleri

- **Blobrunner** ve **jmp2it**, shellcode'ları bellekte tahsis etmek ve Ida veya x64dbg ile hata ayıklamak için araçlardır.
- Blobrunner [sürümleri](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [derlenmiş versiyon](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter**, GUI tabanlı shellcode emülasyonu ve incelemesi sunarak, shellcode'un bir dosya olarak işlenmesi ile doğrudan shellcode işlenmesi arasındaki farkları vurgular.

### Deobfuscation ve Analiz

- **scdbg**, shellcode fonksiyonları ve deobfuscation yetenekleri hakkında bilgiler sunar.
%%%bash
scdbg.exe -f shellcode # Temel bilgi
scdbg.exe -f shellcode -r # Analiz raporu
scdbg.exe -f shellcode -i -r # Etkileşimli kancalar
scdbg.exe -f shellcode -d # Çözülmüş shellcode'u dök
scdbg.exe -f shellcode /findsc # Başlangıç ofsetini bul
scdbg.exe -f shellcode /foff 0x0000004D # Ofsetten çalıştır
%%%

- Shellcode'u ayrıştırmak için **CyberChef**: [CyberChef tarifi](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**

- Tüm talimatları `mov` ile değiştiren bir obfuscator.
- Yararlı kaynaklar arasında bir [YouTube açıklaması](https://www.youtube.com/watch?v=2VF_wPkiBJY) ve [PDF slaytlar](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf) bulunmaktadır.
- **demovfuscator**, movfuscator'ın obfuscation'ını tersine çevirebilir, `libcapstone-dev` ve `libz3-dev` gibi bağımlılıklar gerektirir ve [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) yüklenmelidir.

## **Delphi**

- Delphi ikili dosyaları için, [IDR](https://github.com/crypto2011/IDR) önerilmektedir.

# Kurslar

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Binary deobfuscation\)

{{#include ../../banners/hacktricks-training.md}}
