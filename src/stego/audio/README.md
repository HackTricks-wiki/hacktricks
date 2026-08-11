# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Yaygın kalıplar:

- Spectrogram mesajları
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Hızlı ön inceleme

Özel amaçlı araçları kullanmadan önce:

- Codec/container ayrıntılarını ve anormallikleri doğrulayın:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Audio noise benzeri içerik veya tonal yapı içeriyorsa spectrogram'ı erkenden inceleyin.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego, verilerin zaman/frekans boyunca enerjiyi şekillendirerek gizlenmesini sağlar; böylece veriler bir zaman-frekans grafiğinde görünür hâle gelirken ses tonlar veya gürültü gibi duyulabilir.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Spectrogram incelemesi için birincil araç:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatives

- Audacity (spectrogram görünümü ve filtreler).<sup>[[6]](#references)</sup>
- `sox`, CLI üzerinden spectrogram oluşturabilir:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem çözümleme

Frequency-shift keyed audio, bir spektrogramda genellikle dönüşümlü tek tonlar şeklinde görünür. Yaklaşık merkez/frekans kayması ve baud tahminine sahip olduğunuzda, `minimodem` ile brute force uygulayın:<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem`, Bell ve diğer FSK modlarını ve ayrıca özel mark/space frekanslarını destekler; her kaydın otomatik olarak algılanabileceğini varsaymak yerine seçeneklerine bakın. Çıktı bozuksa `--rx-invert`, açık bir baud modu veya `--samplerate <Hz>` deneyin.<sup>[[4]](#references)</sup>

## WAV LSB

### Technique

Sıkıştırılmamış PCM (WAV) için her sample bir tam sayıdır. Düşük bitlerin değiştirilmesi waveform'u çok az değiştirir; bu nedenle saldırganlar şunları gizleyebilir:

- sample başına 1 bit (veya daha fazlası)
- Kanallar arasında interleaved şekilde
- Bir stride/permutation kullanarak

Karşılaşabileceğiniz diğer audio-hiding aileleri:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (formata ve kullanılan araca bağlı)

### WavSteg

Aşağıdaki komutlar `ragibson/Steganography` toolkit'indeki WavSteg'i kullanır.<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- DeepSound's official repository and releases.<sup>[[7]](#references)</sup>

## DTMF / arama tonları

### Teknik

DTMF, her tuş takımı sinyalini düşük frekans grubundan bir frekans ve yüksek frekans grubundan bir frekans kullanarak temsil eder. Ses, tuş takımı tonlarına veya düzenli çift frekanslı bip seslerine benziyorsa DTMF decoding işlemini erkenden test edin.<sup>[[5]](#references)</sup>

Online decoder'lar:

- `dtmf-detect` browser tool.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, offline audio-file decoder.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa'nın İstek Listesi, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — documentation](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — command-line FSK modem](https://github.com/kamalmostafa/minimodem)
- [5] [ITU-T Recommendation Q.23 — push-button telephone sets için teknik özellikler](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — official repository and releases](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
