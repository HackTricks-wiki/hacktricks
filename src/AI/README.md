# AI u sajber bezbednosti

{{#include ../banners/hacktricks-training.md}}

## Glavni algoritmi mašinskog učenja

Najbolji početak za učenje o AI-ju jeste razumevanje rada glavnih algoritama mašinskog učenja. To će vam pomoći da razumete kako AI funkcioniše, kako da ga koristite i kako da ga napadnete:


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

### Priprema podataka za model i evaluacija

Za podele skupa podataka, klasične metrike i napade na ocenjivanje zasnovano na LLM-u putem ubacivanja sadržaja u odgovore, pogledajte [pripremu podataka za model i evaluaciju](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Arhitektura LLM-ova

Na sledećoj stranici pronaći ćete osnove svake komponente potrebne za izradu osnovnog LLM-a pomoću transformera:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Alati i platforme za modele

Za pokretanje, fino podešavanje, posluživanje ili isprobavanje modela koristite [vodič za alate i platforme za AI modele](AI-Model-Tools-and-Platforms.md).

## Bezbednost AI-ja

### Granice poverenja LLM Gateway-a

Za bezbednost gateway-a pogledajte:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodologija za bezbednost AI agenata

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Okviri za AI rizike

Dva korisna početna okvira za procenu rizika AI sistema jesu OWASP Machine Learning Security Top 10 i Google Secure AI Framework (SAIF). Oni se međusobno dopunjuju i ne predstavljaju iscrpan spisak okvira za AI rizike.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Adversarijalni napadi vođeni mehanističkom interpretabilnošću

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Granice poverenja ugrađenog pregledača u AI-ju

Za mostove pregledača u desktop asistentima, lažiranje adresa kartica i čitanje lokalnih datoteka iz konteksta radnika, pogledajte [granice poverenja ugrađenog pregledača u AI asistentima](AI-Embedded-Browser-Trust-Boundaries.md).

### Bezbednost AI promptova

LLM-ovi su poslednjih godina doveli do naglog porasta upotrebe AI-ja, ali nisu savršeni i mogu se prevariti adversarijalnim promptovima. Ovo je veoma važna tema za razumevanje bezbednog korišćenja AI-ja i načina na koji se može napasti:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE u AI modelima

Programeri i kompanije često pokreću modele preuzete sa Interneta, ali samo učitavanje modela može biti dovoljno za izvršavanje proizvoljnog koda na sistemu. Ovo je veoma važna tema za razumevanje bezbednog korišćenja AI-ja i načina na koji se može napasti:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Zaobilaženje KYC-a uz pomoć AI-ja

Generativni video može da se kombinuje sa ubacivanjem virtuelne kamere i manipulacijom API-ja kamere kako bi se zaobišli slabi KYC, provera starosti i biometrijski postupci provere živosti:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) je otvoreni protokol za povezivanje AI aplikacija sa alatima i izvorima podataka. Pošto MCP serveri mogu da izlažu podatke i radnje, procene moraju da obuhvate autorizaciju, pristanak, validaciju ulaza za alate i proveru granica poverenja.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### A2A protokol između AI agenata

A2A omogućava agentima da se međusobno otkrivaju putem kartice agenta i šalju jedni drugima zadatke preko HTTP-a. Testirajte kartice agenata, autorizaciju zadataka, webhook-ove za push obaveštenja i proširene kartice:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Izložene AI usluge koje se samostalno hostuju

Otkrivanje i testiranje izloženih izvršnih okruženja modela, alata za izradu agenata, demonstracionih ML interfejsa, računarskih klastera i vektorskih baza podataka koji rade bez autentifikacije:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing uz pomoć AI-ja i automatsko otkrivanje ranjivosti


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Pregled izvornog koda i potvrda ranjivosti uz pomoć AI-ja

Za pregled izvora i odredišta podataka, tokove zadataka mobilnih ulaznih tačaka, revizije obrazaca u kernelu i validaciju zasnovanu na dokazima:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Obrnuti inženjering uz pomoć AI-ja

[Delimično podizanje nivoa apstrakcije, otkrivanje invarijantnih MBA izraza, dekodiranje vezano za okruženje i validacija automatskih ekstraktora](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### AI pentester botovi za black-box testiranje veba

Agenti zasnovani na LLM-u mogu da automatizuju dugotrajne black-box tokove rada za pentesting veb aplikacija kada imaju podršku za observabilnost, orkestraciju, obradu autentifikovanih sesija i adversarijalnu validaciju:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Top 10 bezbednosti mašinskog učenja](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Bezbedni AI okvir (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Uvod](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
