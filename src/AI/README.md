# AI u sajber-bezbednosti

{{#include ../banners/hacktricks-training.md}}

## Glavni algoritmi mašinskog učenja

Najbolji način da počnete da učite o AI-ju jeste da razumete kako funkcionišu glavni algoritmi mašinskog učenja. To će vam pomoći da razumete kako AI funkcioniše, kako da ga koristite i kako da ga napadnete:


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

Na sledećoj stranici pronaći ćete osnove svake komponente potrebne za pravljenje osnovnog LLM-a pomoću transformera:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Alati i platforme za modele

Za pokretanje, fine-tuning, posluživanje ili isprobavanje modela koristite [vodič za alate i platforme za AI modele](AI-Model-Tools-and-Platforms.md).

## Bezbednost AI-ja

### Metodologija za bezbednost AI agenata

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Okviri za procenu rizika AI-ja

Dva korisna početna okvira za procenu rizika AI sistema su OWASP Machine Learning Security Top 10 i Google Secure AI Framework (SAIF). Oni se međusobno dopunjuju i ne predstavljaju iscrpan spisak okvira za procenu rizika AI-ja.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Adversarijalni napadi vođeni mehanističkom interpretabilnošću

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Bezbednost AI promptova

LLM-ovi su poslednjih godina doveli do naglog porasta upotrebe AI-ja, ali nisu savršeni i mogu se prevariti adversarijalnim promptovima. Ovo je veoma važna tema za razumevanje bezbedne upotrebe AI-ja i načina na koji se može napasti:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE u AI modelima

Veoma je uobičajeno da programeri i kompanije pokreću modele preuzete sa Interneta, ali samo učitavanje modela može biti dovoljno za izvršavanje proizvoljnog koda na sistemu. Ovo je veoma važna tema za razumevanje bezbedne upotrebe AI-ja i načina na koji se može napasti:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Zaobilaženje KYC provera uz pomoć AI-ja

Generisani video može da se kombinuje sa ubacivanjem virtuelne kamere i manipulacijom API-ja kamere kako bi se zaobišli slabi KYC, provere starosti i postupci za proveru biometrijske živosti:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) je otvoreni protokol za povezivanje AI aplikacija sa alatima i izvorima podataka. Pošto MCP serveri mogu da izlažu podatke i radnje, procene moraju da obuhvate autorizaciju, saglasnost, validaciju ulaza alata i proveru granica poverenja.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing i automatizovano otkrivanje ranjivosti uz pomoć AI-ja


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Pregled izvornog koda i validacija ranjivosti uz pomoć AI-ja

Za pregled source/sink elemenata, tokova zadataka mobilnih ulaznih tačaka, reviziju obrazaca kernela i validaciju zasnovanu na dokazima:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverzno inženjerstvo uz pomoć AI-ja

[Delimična rekonstrukcija koda, otkrivanje invarijanti MBA, dekodiranje vezano za okruženje i validacija automatizovanih ekstraktora](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI pentester botovi

Agenti zasnovani na LLM-ovima mogu da automatizuju dugotrajne black-box web pentesting tokove rada kada im podršku pružaju observabilnost, orkestracija, upravljanje autentifikovanim sesijama i adversarijalna validacija:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP — 10 najvažnijih oblasti bezbednosti mašinskog učenja](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Bezbedni AI okvir (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Uvod](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
