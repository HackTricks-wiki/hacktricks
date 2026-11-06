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

A useful language index is the Esolang wiki.<sup>[[1]](#references)</sup> For ordinary encoding and compression layers, use the [Crypto CTF workflow](../ctf-workflow/). If the clue is invisible text rather than executable syntax, check [text steganography](../../stego/text/).

### Exfiltrating preloaded interpreter state

If a challenge accepts esoteric-language source and runs it in a **custom interpreter**, inspect its initial memory, stack and output instructions before treating the source as a decoding puzzle. When the interpreter preloads a secret onto a Befunge stack, a short program can pop and print the existing bytes without computing them. This requires control of the executed source and an output opcode; it does not work against a normal empty interpreter. In a Befunge challenge, the input below repeatedly emitted characters from a flag preloaded in reverse order on the stack.<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` starts execution to the right, `,` pops and prints a character, and `<` sends the instruction pointer back to `,`. Check the custom interpreter's underflow and instruction-limit behavior: the cited implementation stops when the stack is exhausted or after 1,024 instructions. If the secret is not directly on the stack, inspect other initialized state and available output/read instructions instead of assuming standard Befunge semantics.<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang, the esoteric programming languages wiki](https://esolangs.org/wiki/Main_Page)
- [2] [WolvCTF 2024 Befuddled1 original writeup](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [WolvCTF 2024 Befuddled1 interpreter source](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Befunge language reference](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}
