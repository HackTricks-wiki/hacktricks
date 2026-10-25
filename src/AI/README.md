# AI u sajber-bezbednosti

{{#include ../banners/hacktricks-training.md}}

## Glavni algoritmi mašinskog učenja

Najbolji način da počnete da učite o AI jeste da razumete kako rade glavni algoritmi mašinskog učenja. To će vam pomoći da razumete kako AI funkcioniše, kako da ga koristite i kako da ga napadnete:


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

Na sledećoj stranici pronaći ćete osnove svake komponente potrebne za izradu osnovnog LLM-a pomoću transformera:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Alati i platforme za modele

Za pokretanje, fine-tuning, posluživanje ili isprobavanje modela koristite [AI model tools and platforms guide](AI-Model-Tools-and-Platforms.md).

## Bezbednost AI-ja

### Granice poverenja LLM gateway-a

Za bezbednost gateway-a pogledajte:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodologija za bezbednost AI agenata

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Okviri za procenu rizika AI-ja

Dva korisna početna okvira za procenu rizika AI sistema su OWASP Machine Learning Security Top 10 i Google-ov Secure AI Framework (SAIF). Oni se međusobno dopunjuju i ne predstavljaju iscrpan spisak okvira za procenu rizika AI-ja.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Adversarijalni napadi vođeni mehanističkom interpretabilnošću

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Bezbednost AI promptova

LLM-ovi su poslednjih godina doveli do naglog porasta upotrebe AI-ja, ali nisu savršeni i adversarijalni promptovi ih mogu prevariti. Ovo je veoma važna tema za razumevanje bezbednog korišćenja AI-ja i načina na koje se može napasti:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE u AI modelima

Programeri i kompanije često pokreću modele preuzete sa Interneta, ali i samo učitavanje modela može biti dovoljno za izvršavanje proizvoljnog koda na sistemu. Ovo je veoma važna tema za razumevanje bezbednog korišćenja AI-ja i načina na koje se može napasti:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Zaobilaženje KYC-a uz pomoć AI-ja

Generativni video može se kombinovati sa ubacivanjem virtuelne kamere i manipulacijom API-ja kamere kako bi se zaobišli slabi KYC procesi, provere starosti i provere živosti biometrijskih sistema:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) je otvoreni protokol za povezivanje AI aplikacija sa alatima i izvorima podataka. Pošto MCP serveri mogu da izlažu podatke i radnje, procene moraju obuhvatiti autorizaciju, saglasnost, validaciju ulaza za alate i proveru granica poverenja.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protokol AI agent-ka-agentu (A2A)

A2A omogućava agentima da se međusobno otkrivaju putem agent kartice i šalju jedni drugima zadatke preko HTTP-a. Testirajte agent kartice, autorizaciju zadataka, webhook-ove za push obaveštenja i proširene kartice:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Izložene, samostalno hostovane AI usluge

Otkrivanje otiska i testiranje izloženih pokretača modela, alata za izradu agenata, ML demo interfejsa, računarskih klastera i vektorskih baza podataka koji rade bez autentifikacije:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing uz pomoć AI-ja i automatizovano otkrivanje ranjivosti


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Pregled izvornog koda i validacija ranjivosti uz pomoć AI-ja

Za pregled izvora i ponora, tokove zadataka za ulazne tačke u mobilnim aplikacijama, provere obrazaca u kernelu i validaciju zasnovanu na dokazima:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Obrnuti inženjering uz pomoć AI-ja

[Partial lifting, invariant MBA detection, environment-bound decoding, and automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### AI botovi za black-box web pentesting

Agenti zasnovani na LLM-ovima mogu da automatizuju dugotrajne black-box web pentesting tokove rada ako imaju podršku observability-ja, orkestracije, upravljanja autentifikovanim sesijama i adversarijalne validacije:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 bezbednosti mašinskog učenja](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Bezbedni AI okvir (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Uvod](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
