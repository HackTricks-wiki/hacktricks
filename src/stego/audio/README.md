# Ses Steganografisi

{{#include ../../banners/hacktricks-training.md}}

Yaygın desenler:

- Spectrogram mesajları
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Hızlı ön inceleme

Özel araçları kullanmadan önce:

- Codec/container ayrıntılarını ve anormallikleri doğrulayın:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Ses noise benzeri içerik veya tonal yapı barındırıyorsa, erkenden bir spectrogram inceleyin.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spektrogram steganografisi

### Teknik

Spectrogram stego, verileri zaman/frekans boyunca enerjiyi şekillendirerek gizler; böylece veriler yalnızca bir zaman-frekans grafiğinde görünür hâle gelir (çoğunlukla duyulamaz veya gürültü olarak algılanır).

### Sonic Visualiser

Spektrogram incelemesi için birincil araç:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatifler

- Audacity (spektrogram görünümü, filtreler): https://www.audacityteam.org/
- `sox`, CLI üzerinden spektrogramlar oluşturabilir:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Frequency-shift keyed audio, spectrogram'da genellikle tek tonların dönüşümlü olarak görünmesi şeklindedir.<sup>[[1]](#references)</sup> Yaklaşık bir merkez frekans/kayma ve baud tahmininiz olduğunda, `minimodem` ile brute force uygulayın:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem`, mark/space tonlarını otomatik olarak algılar ve kazancı otomatik ayarlar; çıktı bozuksa `--rx-invert` veya `--samplerate` değerini ayarlayın.

## WAV LSB

### Teknik

Sıkıştırılmamış PCM (WAV) için her sample bir tamsayıdır. Düşük bitlerin değiştirilmesi waveform'u çok az değiştirir; bu nedenle saldırganlar şunları gizleyebilir:

- Sample başına 1 bit (veya daha fazlası)
- Kanallar arasında interleaved
- Bir stride/permutation kullanarak

Karşılaşabileceğiniz diğer audio-hiding aileleri:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format ve tool'a bağlı)

### WavSteg

Kaynak: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / arama tonları

### Teknik

DTMF, karakterleri sabit frekans çiftleri olarak kodlar (telefon tuş takımı). Ses, tuş takımı tonlarına veya düzenli çift frekanslı bip seslerine benziyorsa DTMF decoding'i erkenden test edin.

Online decoder'lar:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Referanslar

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
