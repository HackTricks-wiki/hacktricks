# LLM Training - Priprema podataka

{{#include ../../banners/hacktricks-training.md}}

**Ovo su moje beleške iz veoma preporučene knjige** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **uz neke dodatne informacije.**<sup>[[1]](#references)</sup>

## Osnovne informacije

Za početak pročitajte ovaj tekst kako biste savladali neke osnovne koncepte koje bi trebalo da poznajete:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenizacija

> [!TIP]
> Cilj ove početne faze je veoma jednostavan: **Podeliti ulaz na tokene (ID-jeve) na način koji ima smisla.**


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Uzorkovanje podataka

> [!TIP]
> Cilj ove druge faze je veoma jednostavan: **Uzorkovati ulazne podatke i pripremiti ih za fazu obuke, obično razdvajanjem skupa podataka na rečenice određene dužine i generisanjem očekivanog odgovora.**


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Ugrađivanje tokena

> [!TIP]
> Cilj ove treće faze je veoma jednostavan: **Dodeliti svakom prethodno navedenom tokenu u rečniku vektor željenih dimenzija kako bi se model obučio.** Svaka reč u rečniku biće tačka u prostoru sa X dimenzija.\
> Imajte na umu da se početna pozicija svake reči u prostoru inicijalizuje „nasumično“, a te pozicije predstavljaju parametre koji se mogu obučavati (biće poboljšane tokom obuke).
>
> Pored toga, tokom ugrađivanja tokena **kreira se još jedan sloj ugrađivanja** koji predstavlja (u ovom slučaju) **apsolutnu poziciju reči u rečenici za obuku**. Na ovaj način reč na različitim pozicijama u rečenici imaće drugačiju reprezentaciju (značenje).


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Mehanizmi pažnje

> [!TIP]
> Cilj ove četvrte faze je veoma jednostavan: **Primeni neke mehanizme pažnje**. Oni će se sastojati od velikog broja **ponovljenih slojeva** koji će **obuhvatiti odnos reči u rečniku sa njenim susedima u trenutnoj rečenici koja se koristi za obuku LLM-a**.\
> Za ovo se koristi veliki broj slojeva, pa će veliki broj parametara koji se mogu obučavati prikupljati ove informacije.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. Arhitektura LLM-a

> [!TIP]
> Cilj ove pete faze je veoma jednostavan: **Razviti arhitekturu kompletnog LLM-a**. Objediniti sve, primeniti sve slojeve i kreirati sve funkcije za generisanje teksta ili pretvaranje teksta u ID-jeve i obrnuto.
>
> Ova arhitektura će se koristiti i za obuku i za predviđanje teksta nakon obuke.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training i učitavanje modela

> [!TIP]
> Cilj ove šeste faze je veoma jednostavan: **Obučiti model od nule**. Za ovo će se koristiti prethodna LLM arhitektura, uz petlje koje prolaze kroz skupove podataka i koriste definisane funkcije gubitka i optimizer za obuku svih parametara modela.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA poboljšanja u fine-tuning-u

> [!TIP]
> Upotreba tehnologije **LoRA u velikoj meri smanjuje računarske resurse** potrebne za **fine-tuning** već obučenih modela.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning za klasifikaciju

> [!TIP]
> Cilj ovog odeljka je da prikaže kako se već pre-trained model može fine-tune-ovati tako da, umesto generisanja novog teksta, LLM daje **verovatnoće da dati tekst pripada svakoj od navedenih kategorija** (na primer, da li je tekst spam ili nije).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning za praćenje instrukcija

> [!TIP]
> Cilj ovog odeljka je da prikaže kako se već pre-trained model može **fine-tune-ovati za praćenje instrukcija**, umesto da samo generiše tekst, na primer, odgovaranjem na zadatke kao chatbot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## Reference

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)

{{#include ../../banners/hacktricks-training.md}}
