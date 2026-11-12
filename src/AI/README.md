# AI u sajber-bezbednosti

{{#include ../banners/hacktricks-training.md}}

## Glavni algoritmi mašinskog učenja

Najbolje je početi učenje o AI-ju razumevanjem načina rada glavnih algoritama mašinskog učenja. To će vam pomoći da razumete kako AI funkcioniše, kako da ga koristite i kako da ga napadnete:


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

### Priprema i evaluacija podataka modela

Informacije o podelama skupova podataka, klasičnim metrikama i napadima na strani odgovora pri ocenjivanju zasnovanom na LLM-ovima potražite u vodiču [priprema i evaluacija podataka modela](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Arhitektura LLM-ova

Na sledećoj stranici pronaći ćete osnove svake komponente potrebne za izgradnju osnovnog LLM-a pomoću transformera:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Alati i platforme za modele

Za pokretanje, fino podešavanje, posluživanje ili isprobavanje modela koristite [vodič za alate i platforme za AI modele](AI-Model-Tools-and-Platforms.md).

## Bezbednost AI-ja

### Granice poverenja LLM gateway-a

Informacije o bezbednosti gateway-a potražite ovde:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodologija za bezbednost AI agenata

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Okviri za procenu rizika AI-ja

Dva korisna početna okvira za procenu rizika AI sistema jesu OWASP Machine Learning Security Top 10 i Google-ov Secure AI Framework (SAIF). Oni se međusobno dopunjuju, ali ne predstavljaju iscrpan spisak okvira za procenu rizika AI-ja.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Adversarijalni napadi vođeni mehanističkom interpretabilnošću

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Bezbednost AI promptova

Upotreba AI-ja naglo je porasla poslednjih godina zahvaljujući LLM-ovima, ali oni nisu savršeni i mogu se prevariti adversarijalnim promptovima. Ovo je veoma važna tema za razumevanje bezbednog korišćenja AI-ja i načina na koji se može napasti:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE u AI modelima

Programeri i kompanije često pokreću modele preuzete sa interneta, ali samo učitavanje modela može biti dovoljno za izvršavanje proizvoljnog koda na sistemu. Ovo je veoma važna tema za razumevanje bezbednog korišćenja AI-ja i načina na koji se može napasti:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Zaobilaženje KYC-a uz pomoć AI-ja

Generisani video može se kombinovati sa ubacivanjem virtuelne kamere i manipulacijom API-ja kamere radi zaobilaženja slabih KYC procedura, provera starosti i biometrijskih provera živosti:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) je otvoreni protokol za povezivanje AI aplikacija sa alatima i izvorima podataka. Pošto MCP serveri mogu da izlažu podatke i radnje, procene moraju da obuhvate autorizaciju, saglasnost, validaciju ulaznih podataka alata i proveru granica poverenja.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protokol AI agent-ka-agentu (A2A)

A2A omogućava agentima da se međusobno otkrivaju pomoću agent kartice i šalju jedni drugima zadatke preko HTTP-a. Testirajte agent kartice, autorizaciju zadataka, webhook-ove za push obaveštenja i proširene kartice:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Izložene samostalno hostovane AI usluge

Identifikovanje i testiranje izloženih pokretača modela, alata za izgradnju agenata, korisničkih interfejsa za ML demonstracije, računarskih klastera i vektorskih baza podataka koje rade bez autentifikacije:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing uz pomoć AI-ja i automatizovano otkrivanje ranjivosti


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Pregled izvornog koda i validacija ranjivosti uz pomoć AI-ja

Informacije o pregledu izvora i odredišta, tokovima zadataka za ulazne tačke u mobilnim aplikacijama, proverama obrazaca u kernelu i validaciji zasnovanoj na dokazima potražite ovde:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Obrnuti inženjering uz pomoć AI-ja

[Delimično podizanje nivoa apstrakcije, otkrivanje invarijanti MBA, dekodiranje vezano za okruženje i validacija automatizovanih ekstraktora](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### AI botovi za black-box web pentesting

Agenti zasnovani na LLM-ovima mogu automatizovati dugotrajne black-box web pentesting tokove rada kada imaju podršku observabilnosti, orkestracije, obrade autentifikovanih sesija i adversarijalne validacije:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Top 10 za bezbednost mašinskog učenja](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Bezbedni AI okvir (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Uvod](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
