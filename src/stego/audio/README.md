# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Yaygın desenler:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Hızlı triyaj

Özel araçlara geçmeden önce:

- Codec/container ayrıntılarını ve anomalileri doğrulayın:
- `file audio`
- `ffmpeg -v info -i audio -f null -`

Eğer ses gürültü-benzeri içerik veya tonal bir yapıya sahipse, erken bir spectrogram incelemesi yapın.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Teknik

Spectrogram stego verileri zaman/frekans boyunca enerjiyi şekillendirerek gizler; böylece yalnızca zaman-frekans grafiğinde görünür hale gelir (çoğunlukla işitilemez veya gürültü olarak algılanır).

### Sonic Visualiser

Spectrogram incelemesi için birincil araç:

- https://www.sonicvisualiser.org/

### Alternatifler

- Audacity (spectrogram görünümü, filtreler): https://www.audacityteam.org/
- `sox` komut satırından spectrogramlar oluşturabilir:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Teknik

Sıkıştırılmamış PCM (WAV) için her örnek bir tam sayıdır. Düşük bitleri değiştirmek dalga formunu çok az değiştirir, bu yüzden saldırganlar şunları gizleyebilir:

- Her örnek için 1 bit (ya da daha fazla)
- Kanallar arasında enterleştirilmiş
- Bir stride/permütasyon ile

Karşılaşabileceğiniz diğer ses gizleme teknikleri:

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

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / dial tones

### Teknik

DTMF, karakterleri sabit frekans çiftleri (telefon tuş takımı) olarak kodlar. Eğer ses tuş takımı tonlarına veya düzenli çift frekanslı bip'lere benziyorsa, DTMF çözümlenmesini erken test edin.

Çevrimiçi çözücüler:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}
