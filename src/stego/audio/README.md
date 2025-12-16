# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Yaygın desenler:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Hızlı triyaj

Uzman araçlara geçmeden önce:

- Codec/container detaylarını ve anormallikleri doğrulayın:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Eğer ses gürültü-benzeri içerik veya tonal yapı içeriyorsa, erken aşamada bir spectrogram inceleyin.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Teknik

Spectrogram stego, zamana/frekansa göre enerjiyi şekillendirerek veriyi gizler; böylece yalnızca zaman-frekans grafiğinde görünür olur (çoğunlukla duyulmaz veya gürültü olarak algılanır).

### Sonic Visualiser

Spectrogram incelemesi için birincil araç:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatifler

- Audacity (spectrogram görünümü, filtreler): https://www.audacityteam.org/
- `sox` komut satırından spectrogramlar oluşturabilir:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Teknik

Sıkıştırılmamış PCM (WAV) için her örnek bir tamsayıdır. Düşük bitleri değiştirmek dalga şeklini çok az değiştirir, bu yüzden saldırganlar şunları gizleyebilir:

- Örnek başına 1 bit (veya daha fazlası)
- Kanallar arasında dağıtılmış (interleaved)
- Adım/permütasyon ile

Karşılaşabileceğiniz diğer ses gizleme yöntemleri:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

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

DTMF, karakterleri sabit frekans çiftleri olarak kodlar (telefon tuş takımı). Ses tuş takımı tonlarına veya düzenli çift frekanslı bip'lere benziyorsa, DTMF çözümlemeyi erken test edin.

Çevrimiçi çözücüler:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}
