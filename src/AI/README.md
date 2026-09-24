# AI u cybersecurityju

{{#include ../banners/hacktricks-training.md}}

## Glavni algoritmi mašinskog učenja

Najbolja polazna tačka za učenje o AI jeste razumevanje načina rada glavnih algoritama mašinskog učenja. To će vam pomoći da razumete kako AI funkcioniše, kako da ga koristite i kako da ga napadate:


{{#ref}}
./AI-Supervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Unsupervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Reinforcement-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Deep-Learning.md
{{#endref}}

### Arhitektura LLM-ova

Na sledećoj stranici pronaći ćete osnove svake komponente potrebne za izgradnju osnovnog LLM-a pomoću transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI bezbednost

### Okviri za AI rizike

Dva korisna početna okvira za procenu rizika AI-sistema jesu OWASP Machine Learning Security Top 10 i Google Secure AI Framework (SAIF). Oni se međusobno dopunjuju, ali ne predstavljaju iscrpnu listu okvira za AI rizike.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Bezbednost AI promptova

LLM-ovi su poslednjih godina doveli do naglog širenja upotrebe AI-ja, ali nisu savršeni i mogu biti prevareni adversarial promptovima. Ovo je veoma važna tema za razumevanje bezbedne upotrebe AI-ja i načina na koji se on može napasti:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE u AI modelima

Veoma je uobičajeno da developeri i kompanije pokreću modele preuzete sa Interneta, međutim samo učitavanje modela može biti dovoljno za izvršavanje proizvoljnog koda na sistemu. Ovo je veoma važna tema za razumevanje bezbedne upotrebe AI-ja i načina na koji se on može napasti:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-assisted KYC bypass

Generativni video može da se kombinuje sa virtual-camera injection i manipulacijom camera API-ja kako bi se zaobišli slabi KYC, age-verification i biometric liveness procesi:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) je otvoreni protokol za povezivanje AI aplikacija sa alatima i izvorima podataka. Pošto MCP serveri mogu da izlože podatke i radnje, procene moraju da obuhvate authorization, consent, tool-input validation i proveru granica poverenja.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-assisted fuzzing i automatizovano otkrivanje ranjivosti


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI-assisted reverse engineering

[Partial lifting, invariant MBA detection, environment-bound decoding, and automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

Agenti pokretani pomoću LLM-ova mogu da automatizuju dugotrajne black-box web pentesting procese kada imaju podršku za observability, orchestration, authenticated session handling i adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Uvod](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
