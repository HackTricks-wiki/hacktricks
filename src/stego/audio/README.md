# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Common patterns:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Quick triage

Before specialized tooling:

- Confirm codec/container details and anomalies:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- If the audio contains noise-like content or tonal structure, inspect a spectrogram early.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## Spectrogram steganography

### Technique

Spectrogram stego hides data by shaping energy over time/frequency so it becomes visible only in a time-frequency plot (often inaudible or perceived as noise).

### Sonic Visualiser

Primary tool for spectrogram inspection:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (spectrogram view, filters): https://www.audacityteam.org/
- `sox` can generate spectrograms from the CLI:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## WAV LSB

### Technique

For uncompressed PCM (WAV), each sample is an integer. Modifying low bits changes the waveform very slightly, so attackers can hide:

- 1 bit per sample (or more)
- Interleaved across channels
- With a stride/permutation

Other audio-hiding families you may encounter:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / dial tones

### Technique

DTMF encodes characters as pairs of fixed frequencies (telephone keypad). If the audio resembles keypad tones or regular dual-frequency beeps, test DTMF decoding early.

Online decoders:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}
