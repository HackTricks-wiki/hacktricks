# Ses Steganografisi

{{#include ../../banners/hacktricks-training.md}}

Yaygın kalıplar:

- Spektrogram mesajları
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloadları

## Hızlı ön inceleme

Özel araçları kullanmadan önce:

- Codec/container ayrıntılarını ve anomalileri doğrulayın:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Ses gürültü benzeri içerik veya tonal yapı içeriyorsa spektrogramı erkenden inceleyin.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Teknik

Spectrogram stego, verileri zaman/frekans üzerindeki enerjiyi şekillendirerek gizler; böylece veriler yalnızca bir zaman-frekans grafiğinde görünür hale gelir (çoğunlukla işitilemez veya gürültü olarak algılanır).

### Sonic Visualiser

Spectrogram incelemesi için birincil araç:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatifler

- Audacity (spectrogram görünümü, filtreler): https://www.audacityteam.org/
- `sox`, CLI üzerinden spectrogram oluşturabilir:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Frequency-shift keyed audio, bir spektrogramda genellikle dönüşümlü tek tonlar şeklinde görünür. Yaklaşık center/shift ve baud tahminine sahip olduğunuzda, `minimodem` ile brute force uygulayın:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` mark/space tones'ları otomatik olarak gain'ler ve algılar; çıktı bozuksa `--rx-invert` veya `--samplerate` değerini ayarlayın.

## WAV LSB

### Technique

Sıkıştırılmamış PCM (WAV) için her sample bir tamsayıdır. Düşük bitlerin değiştirilmesi waveform'u çok az değiştirir; bu nedenle saldırganlar şunları gizleyebilir:

- Her sample için 1 bit (veya daha fazlası)
- Kanallar arasında interleaved şekilde
- Bir stride/permutation ile

Karşılaşabileceğiniz diğer audio-hiding family'leri:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent ve tool-dependent)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / dial tones

### Technique

DTMF karakterleri sabit frekans çiftleri olarak kodlar (telefon tuş takımı). Ses, tuş takımı tonlarına veya düzenli çift frekanslı bip seslerine benziyorsa DTMF decoding işlemini erken aşamada test edin.

Online decoders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}
