# Oudiosteganografie

{{#include ../../banners/hacktricks-training.md}}

Algemene patrone:

- Spektrogramboodskappe
- WAV LSB-inbedding
- DTMF-/kiestoonkodering
- Metadata-payloads

## Vinnige triage

Voordat jy gespesialiseerde nutsmiddels gebruik:

- Bevestig kodek-/houerbesonderhede en afwykings:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- As die oudio geraasagtige inhoud of tonale struktuur bevat, ondersoek vroegtydig ’n spektrogram.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## Spectrogram steganography

### Tegniek

Spectrogram-stego versteek data deur energie oor tyd/frekwensie te vorm sodat dit in ’n tyd-frekwensie-grafiek sigbaar word, terwyl die klank soos tone of geraas kan klink.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Primêre hulpmiddel vir spektrogram-inspeksie:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatiewe

- Audacity (spektrogram-aansig en filters).<sup>[[6]](#references)</sup>
- `sox` kan spektrogramme vanaf die CLI genereer:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## FSK / modem-dekodering

FSK-klank lyk dikwels soos afwisselende enkeltone in ’n spektrogram. Sodra jy ’n rowwe skatting van die middelfrekwensie, frekwensieverskuiwing en baudtempo het, brute-forceer met `minimodem`:<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` ondersteun Bell- en ander FSK-modusse, plus pasgemaakte mark-/spasiefrekwensies; raadpleeg die opsies daarvan eerder as om aan te neem dat elke opname outomaties opgespoor kan word. Probeer `--rx-invert`, ’n eksplisiete baud-modus of `--samplerate <Hz>` wanneer die uitvoer deurmekaar is.<sup>[[4]](#references)</sup>

## WAV LSB

### Tegniek

Vir ongekomprimeerde PCM (WAV) is elke sample ’n heelgetal. Deur die lae bisse te verander, verander die golfvorm baie effens, sodat aanvallers die volgende kan versteek:

- 1 bis per sample (of meer)
- Verweef oor kanale
- Met ’n stapgrootte/permutasie

Ander families van oudio-verberging wat jy kan teëkom:

- Fasekodering
- Eggo-verberging
- Verspreidingspektrum-inbedding
- Codec-side kanale (afhanklik van formaat en instrument)

### WavSteg

Die volgende opdragte gebruik WavSteg uit die `ragibson/Steganography`-gereedskapstel.<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- DeepSound se amptelike bewaarplek en vrystellings.<sup>[[7]](#references)</sup>

## DTMF / kiestone

### Tegniek

DTMF stel elke sleutelbordinvoer voor met een frekwensie uit ’n lae groep en een uit ’n hoë groep. As die klank soos sleutelbordtone of gereelde dubbeltoon-piepe klink, toets DTMF-dekodering vroeg.<sup>[[5]](#references)</sup>

Aanlyn-dekodeerders:

- `dtmf-detect`-blaaiernutsding.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, ’n vanlyn oudiolêer-dekodeerder.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pienk, Kersvader se wenslys, Kersmetadata, vasgelegde geraas](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — dokumentasie](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — FSK-modem vir die opdragreël](https://github.com/kamalmostafa/minimodem)
- [5] [ITU-T Recommendation Q.23 — tegniese eienskappe van drukknop-telefoonstelle](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — amptelike bewaarplek en vrystellings](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
