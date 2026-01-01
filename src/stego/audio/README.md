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

## FSK / modem decoding

Frequency-shift keyed audio often looks like alternating single tones in a spectrogram. Once you have a rough center/shift and baud estimate, brute force with `minimodem`:

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` autogains and autodetects mark/space tones; adjust `--rx-invert` or `--samplerate` if the output is garbled.

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

## References

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}

