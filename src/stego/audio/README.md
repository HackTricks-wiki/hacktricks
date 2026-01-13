# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Yaygın kalıplar:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Hızlı ön değerlendirme

Uzman araçlardan önce:

- codec/container ayrıntılarını ve anomalileri doğrulayın:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Eğer ses gürültü-benzeri içerik veya tonal yapı içeriyorsa, erken bir spectrogram incelemesi yapın.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego enerjiyi zaman/frekans boyunca şekillendirerek verileri gizler, böylece yalnızca bir zaman-frekans grafiğinde görünür hale gelir (çoğunlukla duyulmaz veya gürültü olarak algılanır).

### Sonic Visualiser

Spektrogram incelemesi için birincil araç:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatifler

- Audacity (spektrogram görünümü, filtreler): https://www.audacityteam.org/
- `sox` komut satırından spektrogramlar oluşturabilir:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem dekodlama

Frequency-shift keyed ses genellikle spektrogramda dönüşümlü tek tonlar gibi görünür. Yaklaşık bir center/shift ve baud tahminine sahip olduğunuzda, `minimodem` ile brute force yapın:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` otomatik kazanç ayarı yapar ve mark/space tonlarını otomatik olarak algılar; çıktı bozuksa `--rx-invert` veya `--samplerate`'i ayarlayın.

## WAV LSB

### Teknik

Sıkıştırılmamış PCM (WAV) için, her örnek bir tam sayıdır. Düşük bitleri değiştirmek dalga formunu çok az değiştirir; bu nedenle saldırganlar şunları gizleyebilir:

- örnek başına 1 bit (veya daha fazlası)
- Kanallar arasında enterleştirilmiş
- stride/permütasyon ile

Karşılaşabileceğiniz diğer ses gizleme aileleri:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (formata bağlı ve araca bağlı)

### WavSteg

Kaynak: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / tuş tonları

### Teknik

DTMF, karakterleri sabit frekans çiftleri olarak kodlar (telefon tuş takımı). Ses, tuş tonu veya düzenli çift frekanslı bip'lere benziyorsa, DTMF çözümlemesini erken test edin.

Çevrimiçi dekoderler:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Referanslar

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
