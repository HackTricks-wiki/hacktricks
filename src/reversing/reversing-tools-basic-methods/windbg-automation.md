# Hedefli enstrümantasyon için WinDbg otomasyonu

{{#include ../../banners/hacktricks-training.md}}

WinDbg ve WinDbgX, başlangıçta, istisnalarda ve breakpoint'ler tetiklendiğinde debugger komutları çalıştırabilir. Böylece fuzzing veya reversing oturumu, her olayda manuel olarak durmak yerine yalnızca girdinin tetiklediği bir yol çevresindeki durumu toplayabilir.<sup>[[1]](#references)</sup>

## Yararlı bir istisnada başlatma

`-c`, debugger'ın ilk duraklamasında komutları çalıştırır. Kurulumdan sonra devam etmek için sonuna `;g` ekleyin. Gözetimsiz bir WinDbg Classic çalıştırmasında `-logo`, komut penceresini bir log dosyasına yazar; `-Q`, çalışma alanının otomatik kaydedilmesini devre dışı bırakır; `-G` ise son breakpoint'i yok sayarak hedef sonlandığında oturumu bitirir. WinDbgX de `-c` seçeneğini kabul eder; yapılandırılmış Startup commands komutları daha sonra çalıştırılır.<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

Access violation durumlarında **`sxe av` ilk şansta keser**, **`sxd av` ilk şansı atlar ancak işlenmeyen ikinci şansta keser** ve **`sxi av` her iki şansı da yok sayar**. Makaledeki `sxi`/`sxd` açıklamaları burada tersine çevrilmiş: Microsoft, `sxd`'yi ikinci şans filtresi, `sxi`'yi ise yok sayma filtresi olarak belgeliyor. İlk şans komutu için `-c`, ikinci şans komutu için `-c2` kullanın; filtre `sxd` olsa bile ilk şans `-c` işleyicisi ikinci şans işleyicisine dönüşmez. Etkin filtreleri `sx` ile doğrulayın.<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

İlk komut yalnızca işlenmeyen bir access violation durumunda register’ları, stack trace’i ve exception analizini toplar. İkinci komut, bir modül yüklendiğinde `lm` komutunu çalıştırır. Breakpoint (`bp`), modül yükleme (`ld`) ve access violation (`av`) olaylarının yaşam döngüleri farklıdır; bu nedenle debugger breakpoint’lerine güveniyorsanız `bp` olaylarını genel olarak yok saymayın.<sup>[[1]](#references)[[2]](#references)</sup>

## Kontrollü bir tetikleyiciyle maliyetli breakpoint’leri etkinleştirin

İlgilendiğiniz yoldan hemen önce çağrılabilecek, script tarafından görülebilen veya başka şekilde girdiyle kontrol edilebilen bir işlev seçin. İncelemek istediğiniz allocator, parser veya API çağrılarına **action breakpoint**’ler ekleyin. Bunları kimlikleriyle `bd` kullanarak devre dışı bırakın. Komutuyla bu kimlikleri `be` kullanarak etkinleştiren ve ardından `g` ile devam eden bir **trigger breakpoint** ekleyin; ikinci bir kontrollü tetikleyiciyle bunları yeniden devre dışı bırakabilirsiniz. Tetikleyiciyi ayarlamadan önce `bl` ile kimlikleri kontrol edin; çünkü kimlikler breakpoint’lerin oluşturulma sırasına bağlıdır. Böylece düşük maliyetli kontrol noktaları, maliyetli izleme işlemlerinden ayrılır ve hedefin zamanlamasıyla heap yerleşimindeki değişiklikler sınırlandırılır.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

İki sembolü çözdükten sonra aşağıdaki komut kalıbını kullanın. Köşeli parantez içindeki sembolleri ve `bl` tarafından döndürülen action breakpoint kimliğini değiştirin; bu kimliğin sıfır olduğunu varsaymayın.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Action breakpoint komutları `@$ip` ve `%y` (sembolleştirilmiş adres) yazdırabilir, seçili argümanları veya belleği dökebilir ve ardından devam edebilir. Koşullu bir breakpoint yalnızca seçilen aralıktaki pointer'ları kaydediyorsa, önce aralığın test girdisini gerçekten kapsadığını doğrulayın; yanlış bir koşul kanıtları sessizce kaybettirir.<sup>[[1]](#references)</sup>

### Sembollerle bir tetikleyici bulun

Uygulamanın bulunduğu modül bilinmiyorsa, yüklü tüm modüllerde arama yapın. `bm` eşleşen her sembole breakpoint koyar; script tarafından erişilebilir işlevi çağırın ve hangi breakpoint'in tetiklendiğini inceleyin. Örneğin kaynak kod, herhangi bir browser process'inde değil, debug edilen renderer'da `Math.cos(0)` çağrısını çalıştırır.<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

Bir eşleşme tam işlevi belirlediğinde, işlevin bulunduğu image'ı çözümlemek için `lm a <symbol>` komutunu, modüle göreli offset'i hesaplamak için `? <symbol> - <module>` komutunu kullanın. WinDbg, bir executable ve DLL için aynı kısa modül adını gösterebilir; bu nedenle offset'i başka bir process'te kullanmadan önce image path'ini doğrulayın. Ek yükü önlemek için wildcard breakpoint'leri doğrulanmış sembolle sınırlayın.<sup>[[1]](#references)</sup>

### Sembol olmadan bir aday bulun

Corelan'ın Frida tabanlı `corelan_trigscan.py` aracı, seçilen bir process modülünü floating-point, SSE, AVX ve trigonometrik instruction örüntüleri açısından tarar. WinDbg breakpoint komutlarını `corelan_trigscan.bps` dosyasına ve numaralandırılmış daha küçük `.bps` dosyalarına yazar. Aracı Python ve `frida-tools` ile, hedefte **başka bir debugger bağlı değilken** çalıştırın; ardından aynı process/module'a WinDbg ile bağlanıp yönetilebilir büyüklükte bir breakpoint grubunu yükleyin.<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

Bilinen bir modüle göreli ofsetin, oluşturulan tüm breakpoint'ler içe aktarılmadan önce eşikleri geçtiğini doğrulayın:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` ilgili talimat yoğunluğunu belirtir, `--min-relevant` ve `--min-total` talimat sayısı alt sınırlarını belirler, `--min-trig` ise güçlü trig benzeri sinyaller gerektirir. Bilinen bir işlev gözden kaçarsa prologunu, yoğunluğunu, sayılarını ve dolaylı çağrılarını incelemek için `--check-offset` seçeneğine **modüle göreli** offset değerini verin. İnce bir wrapper'ın yoğunluğu düşük olabilir ve trig talimatı içermeyebilir. Eşikleri düşürün ve wrapper arıyorsanız betiğin gerçek `--min-icall 1` seçeneğini kullanın (`--min-ical` değil); doğrudan çağrılanlar analiz edilir, ancak dolaylı hedefler güvenilir biçimde izlenemez. Çok sayıda oluşturulan breakpoint WinDbg'yi yavaşlattığında daha küçük `--splitsize` grupları yardımcı olur. Aday, hedeflenen girdi breakpoint'i tetikleyene kadar doğrulanmış sayılmaz.<sup>[[1]](#references)[[6]](#references)</sup>

## Küçük hata ayıklayıcı programları ve PyKD

Bir koşul güvenilir olduğunda `.if`, boşluklarla ayrılmış çıktıda yineleme yapmak için `.foreach`, bellek veya yapılar üzerinde gezinmek için pseudo-register'larla `.for` kullanın. `.foreach` sütunları korumaz: Örneğin, değişken genişlikli `lm` çıktısı uygun bir girdi değildir; `lm 1m` ise her token için bir modül adı üretir. Tahmin edilen bir koşulun hatalı yolu gizleyebileceği durumlarda, önce filtrelenmemiş verileri günlüğe kaydedin.<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

`as name value` ile oluşturulan alias'lar, türü belirlenmiş değişkenler değil, metinsel ikamelerdir. `al` alias'ları listeler, `ad name` bir alias'ı siler ve `${name}` belirsiz olmayan genişletmeyi zorlar. Bir alias yerleşik bir komutu gölgeleyebileceği için `bp`, `x` veya `r` gibi adlardan kaçının. MASM ifadeleri `poi(@$t0)` gibi işaretçi aritmetiği için uygundur; semboller mevcut olduğunda `@@c++(...)` sabit kodlanmış yapı ofsetlerinden kaçınarak türü belirlenmiş alanlara erişebilir.<sup>[[1]](#references)</sup>

Daha uzun komut dizilerini bir komut dosyasına koyun. `$$><filename` satırları tek bir komut bloğunda birleştirir ve ardından noktalı virgülle ayrılmış bir hata ayıklayıcı komutunun kullanılmasına izin verir. Çok satırlı kontrol yapıları yine de sorun çıkarabilir; her `.if` veya `.for` ifadesini tek satırda tutun. Aynı dosya başlangıçta `-c` seçeneğinden de çağrılabilir.<sup>[[1]](#references)[[8]](#references)</sup>

Komut dilinde yazılması zahmetli olan mantıklar için PyKD; türü belirlenmiş yapıları, register'ları, belleği ve hata ayıklayıcı çıktısını Python'a sunar. Örneğin, `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` PEB alanlarına erişir, `pykd.loadBytes(address, size)` belleği okur ve `pykd.dbgCommand("lm")` ayrıştırılmak üzere hata ayıklayıcı çıktısını döndürür. Sonlandırılmamış olabilecek veriler için sınırsız dize okumaları yerine sınırlandırılmış `loadChars`/`loadWChars` kullanmayı tercih edin. PyKD'deki `disasm(address).asm(instruction)`, **birleştirilmiş baytları o adrese yazar**; canlı bir süreçte opcode'ları elde etmek için kullanıyorsanız orijinal belleği saklayıp geri yükleyin.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: Hata Ayıklama - WinDBG(X) Otomasyonu ve Betik Yazımı - Bölüm 1](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx, sxd, sxe, sxi, sxn, sxr, sx- (İstisnaları Ayarlama)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be (Kesme Noktasını Etkinleştirme)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd (Kesme Noktasını Devre Dışı Bırakma)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp, bu, bm (Kesme Noktası Ayarlama)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Corelan trigscan kaynak kodu](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: WinDbg Komut Satırı Seçenekleri](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: Betik Dosyasını Çalıştırma](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
