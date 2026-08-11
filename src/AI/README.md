# AI u sajber-bezbednosti

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

Na sledećoj stranici pronaći ćete osnove svake komponente potrebne za izgradnju osnovnog LLM-a pomoću transformera:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Bezbednost AI-ja

### Okviri za AI rizike

Dva korisna početna okvira za procenu rizika AI sistema jesu OWASP Machine Learning Security Top 10 i Google-ov Secure AI Framework (SAIF). Oni se međusobno dopunjuju, a ne predstavljaju iscrpan spisak okvira za AI rizike.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Bezbednost AI promptova

LLM-ovi su poslednjih godina naglo proširili upotrebu AI-ja, ali nisu savršeni i mogu biti prevareni adversarial promptovima. Ovo je veoma važna tema za razumevanje bezbednog korišćenja AI-ja i načina njegovog napadanja:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE AI modela

Veoma je uobičajeno da developeri i kompanije pokreću modele preuzete sa Interneta; međutim, samo učitavanje modela može biti dovoljno za izvršavanje proizvoljnog koda na sistemu. Ovo je veoma važna tema za razumevanje bezbednog korišćenja AI-ja i načina njegovog napadanja:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KYC bypass uz pomoć AI-ja

Generativni video može da se kombinuje sa injectionom virtuelne kamere i manipulacijom camera API-ja radi zaobilaženja slabih KYC procedura, verifikacije uzrasta i provera biometrijske prisutnosti:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol za AI

MCP (Model Context Protocol) je otvoreni protokol za povezivanje AI aplikacija sa alatima i izvorima podataka. Pošto MCP serveri mogu da izlože podatke i radnje, procene moraju da obuhvate autorizaciju, saglasnost, validaciju unosa alata i proveru granica poverenja.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing uz pomoć AI-ja i automatizovano otkrivanje ranjivosti


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester botovi

Agenti pokretani pomoću LLM-a mogu da automatizuju dugotrajne black-box web pentesting tokove kada imaju podršku za observability, orkestraciju, upravljanje autentifikovanim sesijama i adversarial validaciju:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 bezbednosti mašinskog učenja](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Uvod](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
