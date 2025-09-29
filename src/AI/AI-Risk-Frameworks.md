# AI rizici

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 ranjivosti mašinskog učenja

Owasp je identifikovao top 10 ranjivosti mašinskog učenja koje mogu uticati na AI sisteme. Ove ranjivosti mogu dovesti do raznih bezbednosnih problema, uključujući data poisoning, model inversion i adversarial attacks. Razumevanje ovih ranjivosti je ključno za izgradnju sigurnih AI sistema.

For an updated and detailed list of the top 10 machine learning vulnerabilities, refer to the [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) project.

- **Input Manipulation Attack**: Napadač dodaje male, često nevidljive izmene u **dolazne podatke** kako bi model doneo pogrešnu odluku.\
*Primer*: Nekoliko tačkica boje na stop‑sign zbuni self‑driving automobil tako da "vidi" saobraćajni znak za ograničenje brzine.

- **Data Poisoning Attack**: **skup za treniranje** je namerno zagađen lošim uzorcima, učeći model štetnim pravilima.\
*Primer*: Malware binarni fajlovi su pogrešno označeni kao "benign" u antivirus trening korpusu, što omogućava sličnom malware‑u da kasnije prolazi neprimećeno.

- **Model Inversion Attack**: Ispitujući izlaze, napadač gradi **reverse model** koji rekonstruiše osetljive karakteristike originalnih ulaza.\
*Primer*: Rekreiranje MRI slike pacijenta iz predikcija modela za detekciju raka.

- **Membership Inference Attack**: Adversar testira da li je **konkretan zapis** korišćen tokom treniranja uočavajući razlike u poverenju.\
*Primer*: Potvrđivanje da se nečija bankarska transakcija pojavljuje u trening podacima modela za detekciju prevara.

- **Model Theft**: Ponavljanim upitima napadač uči granice odluke i **klonira ponašanje modela** (i IP).\
*Primer*: Prikupljanje dovoljnih Q&A parova iz ML‑as‑a‑Service API‑ja da se izgradi gotovo ekvivalentan lokalni model.

- **AI Supply‑Chain Attack**: Kompromitovanje bilo koje komponente (podataka, biblioteka, pre‑trained weights, CI/CD) u **ML pipeline** da bi se pokvarili downstream modeli.\
*Primer*: Poisoned dependency na model‑hub instalira backdoored sentiment‑analysis model u mnoge aplikacije.

- **Transfer Learning Attack**: Zlonamerna logika je ubačena u **pre‑trained model** i preživi fine‑tuning na zadatku žrtve.\
*Primer*: Vision backbone sa skrivenim trigger‑om i dalje menja oznake nakon adaptacije za medicinsko snimanje.

- **Model Skewing**: Suptilno pristrasni ili pogrešno označeni podaci **pomera izlaze modela** da favorizuju napadačevu agendu.\
*Primer*: Usporavanje "clean" spam mejlova označenih kao ham tako da spam filter pusti slične buduće mejlove.

- **Output Integrity Attack**: Napadač **menja predikcije modela u prenosu**, a ne sam model, zavaravajući downstream sisteme.\
*Primer*: Preokretanje verdict‑a malware klasifikatora iz "malicious" u "benign" pre nego što faza karantinovanja fajla to vidi.

- **Model Poisoning** --- Direktne, ciljne izmene u **parametrima modela** same po sebi, često nakon sticanja write pristupa, kako bi se promenilo ponašanje.\
*Primer*: Podešavanje weights na fraud‑detection modelu u produkciji tako da transakcije sa određenih kartica uvek bivaju odobrene.


## Google SAIF rizici

Google's [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) opisuje različite rizike povezane sa AI sistemima:

- **Data Poisoning**: Zlonamerni akteri menjaju ili ubacuju trening/tuning podatke da degradiraju tačnost, implantiraju backdoore ili iskrivljuju rezultate, potkopavajući integritet modela kroz ceo data‑lifecycle.

- **Unauthorized Training Data**: Uvođenje zaštićenih autorskim pravima, osetljivih ili neodobrenih dataset‑ova stvara pravne, etičke i performansne obaveze jer model uči iz podataka koje nije smeo da koristi.

- **Model Source Tampering**: Supply‑chain ili insider manipulacija model code, dependencies ili weights pre ili tokom treniranja može ugraditi skrivenu logiku koja opstaje i nakon retraining‑a.

- **Excessive Data Handling**: Slabe kontrole zadržavanja i upravljanja podacima dovode do toga da sistemi čuvaju ili procesuiraju više personalnih podataka nego što je potrebno, povećavajući izloženost i rizik od neusaglašenosti.

- **Model Exfiltration**: Napadači kradu model fajlove/weights, uzrokujući gubitak intelektualne svojine i omogućavajući copy‑cat servise ili naknadne napade.

- **Model Deployment Tampering**: Adversar menja model artifacts ili serving infrastrukturu tako da pokrenuti model razlikuje se od verificirane verzije, potencijalno menjajući ponašanje.

- **Denial of ML Service**: Poplava API‑ja ili slanje “sponge” inputa može iscrpeti compute/energiju i oboriti model offline, što podseća na klasične DoS napade.

- **Model Reverse Engineering**: Prikupljanjem velikog broja input‑output parova, napadači mogu klonirati ili distilovati model, podstičući imitacione proizvode i prilagođene adversarial napade.

- **Insecure Integrated Component**: Ranljivi plugin‑ovi, agenti ili upstream servisi dopuštaju napadačima da ubace kod ili eskaliraju privilegije unutar AI pipeline‑a.

- **Prompt Injection**: Konstruisanje promptova (direktno ili indirektno) da unesu instrukcije koje nadjačavaju sistemski intent, navodeći model da izvrši neželjene komande.

- **Model Evasion**: Pažljivo dizajnirani inputi izazivaju model da pogrešno klasifikuje, hallucinate ili iskaže zabranjeni sadržaj, urušavajući sigurnost i poverenje.

- **Sensitive Data Disclosure**: Model otkriva privatne ili poverljive informacije iz svojih trening podataka ili korisničkog konteksta, kršeći privatnost i regulative.

- **Inferred Sensitive Data**: Model izvodi lične atribute koji nikada nisu bili dostavljeni, stvarajući nove štete po privatnost putem inferencije.

- **Insecure Model Output**: Nesanitizovani odgovori prosleđuju štetan kod, dezinformacije ili neprikladan sadržaj korisnicima ili downstream sistemima.

- **Rogue Actions**: Autonomno integrisani agenti izvršavaju neželjene real‑world operacije (pisanje fajlova, API pozivi, kupovine, itd.) bez adekvatnog nadzora korisnika.

## Mitre AI ATLAS Matrix

The [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) pruža obuhvatni okvir za razumevanje i ublažavanje rizika povezanih sa AI sistemima. Kategorizuje različite tehnike napada i taktike koje adversari mogu koristiti protiv AI modela i takođe kako koristiti AI sisteme za izvođenje različitih napada.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Napadači kradu aktivne session tokene ili cloud API kredencijale i pozivaju plaćene, cloud-hosted LLM‑ove bez autorizacije. Pristup se često preprodaje preko reverse proxy‑a koji stoje ispred naloga žrtve, npr. "oai-reverse-proxy" deploymenti. Posledice uključuju finansijski gubitak, zloupotrebu modela van politike i atribuciju na tenant‑a žrtve.

TTPs:
- Harvest tokens sa inficiranih developer mašina ili browsera; steal CI/CD secrets; buy leaked cookies.
- Podizanje reverse proxy‑ja koji prosleđuje zahteve pravom provajderu, skrivajući upstream key i multiplexing mnogo korisnika.
- Abuse direct base‑model endpoints da se zaobiđu enterprise guardrails i rate limits.

Mitigations:
- Bind tokens na device fingerprint, IP opsege i client attestation; enforce short expirations i refresh sa MFA.
- Scope keys minimalno (no tool access, read‑only gde je primenljivo); rotate na anomaliju.
- Terminate sav traffic server‑side iza policy gateway‑a koji sprovodi safety filters, per‑route kvote i tenant isolation.
- Monitor za neuobičajene obrasce korišćenja (nagli skokovi potrošnje, netipične regije, UA stringovi) i auto‑revoke sumnjive sesije.
- Prefer mTLS ili signed JWTs issued by your IdP over dugotrajnim statičkim API ključevima.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
