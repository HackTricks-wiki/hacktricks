# Ses Steganografisi

{{#include ../../banners/hacktricks-training.md}}

Yaygın örüntüler:

- Spektrogram mesajları
- WAV LSB gömme
- DTMF / arama tonu kodlaması
- Metadata payload’ları

## Hızlı ön inceleme

Özel araçları kullanmadan önce:

- Codec/container ayrıntılarını ve anormallikleri doğrulayın:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- Ses gürültü benzeri içerik veya tonal yapı içeriyorsa spektrogramı erkenden inceleyin.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## Spektrogram steganografisi

### Teknik

Spektrogram stego, enerjiyi zaman/frekans boyunca şekillendirerek verileri zaman-frekans grafiğinde görünür hâle getirir; ses ise ton veya gürültü gibi duyulabilir.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Spektrogram incelemesi için birincil araç:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatifler

- Audacity (spektrogram görünümü ve filtreler).<sup>[[6]](#references)</sup>
- `sox`, CLI üzerinden spektrogram oluşturabilir:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## FSK / modem çözümleme

Frekans kaydırmalı anahtarlamalı ses, spektrogramda genellikle dönüşümlü tek tonlar şeklinde görünür. Yaklaşık merkez frekansı/kayma ve baud tahminini yaptıktan sonra `minimodem` ile kaba kuvvet deneyin:<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem`, Bell ve diğer FSK modlarını ve özel mark/space frekanslarını destekler; her kaydın otomatik olarak algılanabileceğini varsaymak yerine seçeneklerine bakın. Çıktı bozuksa `--rx-invert`, açıkça belirtilmiş bir baud modu veya `--samplerate <Hz>` deneyin.<sup>[[4]](#references)</sup>

## WAV LSB

### Teknik

Sıkıştırılmamış PCM (WAV) için her örnek bir tam sayıdır. Düşük bitleri değiştirmek dalga biçimini çok az etkiler; bu nedenle saldırganlar şunları gizleyebilir:

- Örnek başına 1 bit (veya daha fazla)
- Kanallar arasında iç içe
- Bir adım aralığı/permütasyon kullanarak

Karşılaşabileceğiniz diğer ses gizleme yöntemleri:

- Faz kodlama
- Yankı gizleme
- Yayılı spektrum gömme
- Codec tarafı kanalları (biçime ve araca bağlı)

### WavSteg

Aşağıdaki komutlarda `ragibson/Steganography` araç setindeki WavSteg kullanılır.<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- DeepSound'un resmi deposu ve sürümleri.<sup>[[7]](#references)</sup>

## DTMF / arama tonları

### Teknik

DTMF, her tuş sinyalini düşük frekans grubundan bir frekans ve yüksek frekans grubundan bir frekans kullanarak temsil eder. Ses tuş takımı tonlarına veya düzenli çift frekanslı bip seslerine benziyorsa, DTMF kod çözmeyi erkenden deneyin.<sup>[[5]](#references)</sup>

Çevrimiçi kod çözücüler:

- `dtmf-detect` tarayıcı aracı.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, çevrimdışı bir ses dosyası kod çözücüsü.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pembe, Noel Baba'nın İstek Listesi, Noel Metadata'sı, Yakalanan Gürültü](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — belgeler](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — komut satırı FSK modem](https://github.com/kamalmostafa/minimodem)
- [5] [ITU-T Recommendation Q.23 — tuşlu telefon setlerinin teknik özellikleri](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — resmi depo ve sürümler](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
