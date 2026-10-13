# LLM-Assisted Password Candidate Generation

{{#include ../banners/hacktricks-training.md}}

## Reuse recovered passwords with a local model

When an offline Hashcat pass has already recovered some passwords, [hate_crack](../generic-hacking/brute-force.md#target-trained-hashcat-passes-with-hate_crack) can feed the current session's plaintexts to an LLM and test newly generated candidates. Its LLM attack (main menu `12`) offers **Cracked passwords** (submenu `3`) only after `<hashfile>.out` is nonempty. This asks the model to generalize the target's observed basewords, years, suffixes, casing and other conventions instead of applying only a fixed rule file.<sup>[[1]](#references)[[2]](#references)</sup>

Configure a model already served by local Ollama in hate_crack's `.env`, then launch the same hash file and Hashcat mode used in the first pass.<sup>[[1]](#references)[[2]](#references)</sup> The model is not pulled automatically.<sup>[[1]](#references)</sup> `OLLAMA_NO_CLOUD=true` matters even if `OLLAMA_HOST` is localhost: an Ollama `-cloud` model can proxy prompts to a remote service through that local endpoint. The no-cloud setting rejects such models and nonlocal destinations before recovered plaintexts or corpus statistics are sent.<sup>[[1]](#references)</sup>

```dotenv
LLM_BACKEND=ollama
OLLAMA_HOST=localhost:11434
OLLAMA_MODEL=qwen3:4b-instruct
OLLAMA_NO_CLOUD=true
```

```bash
hate_crack hashes.txt 1000
# Select 12 (LLM Attack), then 3 (Cracked passwords).
```

The model's output is tested by Hashcat as candidates; it does not bypass the password hash.<sup>[[1]](#references)[[2]](#references)</sup> Compare its cracking yield with cheaper [rules, masks and target-trained generators](../generic-hacking/brute-force.md#target-trained-hashcat-passes-with-hate_crack) before spending a larger budget.

## References

- [1] [hate_crack repository and LLM attack configuration](https://github.com/trustedsec/hate_crack)
- [2] [What's New in hate_crack Since 2.0](https://trustedsec.com/blog/whats-new-in-hate-crack-since-2-0)

{{#include ../banners/hacktricks-training.md}}
