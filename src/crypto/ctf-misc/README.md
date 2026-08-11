# Crypto CTF Misc

{{#include ../../banners/hacktricks-training.md}}

This section collects techniques that appear in cryptography challenges but do not fit neatly into the other categories.

## Esoteric languages

### Technique

Use this workflow when a challenge requires running an esoteric-language program and decoding its output.

If a challenge gives you code that does not look like a standard language:

- Identify the language by searching for a distinctive token or instruction sequence.
- Use an online interpreter or a Docker image.
- If the output is weird, look for layered encoding/compression after execution.

A useful language index is the Esolang wiki.<sup>[[1]](#references)</sup>

## References

- [1] [Esolang, the esoteric programming languages wiki](https://esolangs.org/wiki/Main_Page)

{{#include ../../banners/hacktricks-training.md}}
