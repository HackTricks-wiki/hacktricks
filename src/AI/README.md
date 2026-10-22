# AI u sajber-bezbednosti

{{#include ../banners/hacktricks-training.md}}

## Glavni algoritmi mašinskog učenja

Najbolje je početi učenje o AI-ju razumevanjem rada glavnih algoritama mašinskog učenja. To će vam pomoći da razumete kako AI funkcioniše, kako da ga koristite i kako da ga napadnete:


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

Za pokretanje, dodatno treniranje, posluživanje ili isprobavanje modela koristite [vodič za alate i platforme za AI modele](AI-Model-Tools-and-Platforms.md).

## Bezbednost AI-ja

### Granice poverenja LLM gateway-a

Za bezbednost gateway-a pogledajte:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodologija bezbednosti AI agenata

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

LLM-ovi su poslednjih godina doveli do naglog porasta upotrebe AI-ja, ali nisu savršeni i mogu se prevariti adversarijalnim promptovima. Ovo je veoma važna tema za razumevanje bezbedne upotrebe AI-ja i načina na koje se može napasti:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE u AI modelima

Programeri i kompanije često pokreću modele preuzete sa interneta, ali samo učitavanje modela može biti dovoljno za izvršavanje proizvoljnog koda na sistemu. Ovo je veoma važna tema za razumevanje bezbedne upotrebe AI-ja i načina na koje se može napasti:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Zaobilaženje KYC-a uz pomoć AI-ja

Generativni video može se kombinovati sa ubacivanjem virtuelne kamere i manipulacijom API-ja kamere radi zaobilaženja slabih KYC, provera starosti i postupaka biometrijske provere prisutnosti:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol za AI

MCP (Model Context Protocol) je otvoreni protokol za povezivanje AI aplikacija sa alatima i izvorima podataka. Pošto MCP serveri mogu da izlažu podatke i radnje, procene moraju da obuhvate autorizaciju, saglasnost, validaciju ulaza za alate i pregled granica poverenja.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing uz pomoć AI-ja i automatizovano otkrivanje ranjivosti


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Pregled izvornog koda i potvrđivanje ranjivosti uz pomoć AI-ja

Za pregled izvora i odredišta, tokova zadataka za mobilne ulazne tačke, revizije obrazaca u kernelu i potvrđivanje uz proveru dokaza:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverzno inženjerstvo uz pomoć AI-ja

[Delimično podizanje nivoa apstrakcije, otkrivanje invarijanti MBA, dekodiranje vezano za okruženje i validacija automatizovanih ekstraktora](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### AI botovi za black-box web pentesting

Agenti zasnovani na LLM-ovima mogu da automatizuju dugotrajne black-box web pentesting tokove rada kada imaju podršku u vidu observabilnosti, orkestracije, upravljanja autentifikovanim sesijama i adversarijalne validacije:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 bezbednosti mašinskog učenja](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Bezbedni AI okvir (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Uvod](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
