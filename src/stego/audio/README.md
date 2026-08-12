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

Spectrogram stego hides data by shaping energy over time/frequency so it becomes visible in a time-frequency plot, while the audio may sound like tones or noise.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Primary tool for spectrogram inspection:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternatives

- Audacity (spectrogram view and filters).<sup>[[6]](#references)</sup>
- `sox` can generate spectrograms from the CLI:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## FSK / modem decoding

Frequency-shift keyed audio often looks like alternating single tones in a spectrogram. Once you have a rough center/shift and baud estimate, brute force with `minimodem`:<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` supports Bell and other FSK modes plus custom mark/space frequencies; consult its options rather than assuming every recording can be autodetected. Try `--rx-invert`, an explicit baud mode, or `--samplerate <Hz>` when output is garbled.<sup>[[4]](#references)</sup>

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

The following commands use WavSteg from the `ragibson/Steganography` toolkit.<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- DeepSound's official repository and releases.<sup>[[7]](#references)</sup>

## DTMF / dial tones

### Technique

DTMF represents each keypad signal using one frequency from a low group and one from a high group. If the audio resembles keypad tones or regular dual-frequency beeps, test DTMF decoding early.<sup>[[5]](#references)</sup>

Online decoders:

- `dtmf-detect` browser tool.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, an offline audio-file decoder.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — documentation](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — command-line FSK modem](https://github.com/kamalmostafa/minimodem)
- [5] [ITU-T Recommendation Q.23 — technical features of push-button telephone sets](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — official repository and releases](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)

{{#include ../../banners/hacktricks-training.md}}
