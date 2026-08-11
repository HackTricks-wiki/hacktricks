# LLM Training - Priprema podataka

{{#include ../../banners/hacktricks-training.md}}

**Ovo su moje beleške iz veoma preporučene knjige** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **uz neke dodatne informacije.**<sup>[[1]](#references)</sup>

## Osnovne informacije

Trebalo bi da počnete čitanjem ovog posta o osnovnim konceptima koje bi trebalo da poznajete:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> Cilj ove faze je **podeliti ulaz na tokene i mapirati ih na ID-jeve tokena**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> Cilj ove faze je pripremiti sekvence za trening izabrane dužine konteksta, zajedno sa njihovim pomerenim ciljevima predikcije.


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> Cilj ove treće faze je veoma jednostavan: **Dodeliti svakom od prethodnih tokena u vokabularu vektor željenih dimenzija za treniranje modela.** Svaka reč u vokabularu biće tačka u prostoru sa X dimenzija.\
> Imajte na umu da se početna pozicija svake reči u prostoru inicijalizuje „nasumično“ i da su te pozicije trainable parameters (biće poboljšane tokom treninga).
>
> Pored toga, tokom token embedding-a, **kreira se još jedan embedding layer** koji predstavlja (u ovom slučaju) **apsolutnu poziciju reči u rečenici za trening**. Na ovaj način, reč na različitim pozicijama u rečenici ima različitu reprezentaciju.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> Cilj ove četvrte faze je veoma jednostavan: **Primeniti neke attention mechanisms**. Oni će se sastojati od velikog broja **ponovljenih layer-a** koji će **uhvatiti odnos reči u vokabularu sa njenim susedima u trenutnoj rečenici koja se koristi za treniranje LLM-a**.\
> Za ovo se koristi veliki broj layer-a, pa će veliki broj trainable parameters hvatati ove informacije.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> Cilj ove pete faze je veoma jednostavan: **Razviti arhitekturu kompletnog LLM-a**. Sve treba objediniti, primeniti sve layer-e i kreirati sve funkcije za generisanje teksta ili pretvaranje teksta u ID-jeve i obrnuto.
>
> Ova arhitektura će se koristiti i za trening i za predikciju teksta nakon treninga.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> Cilj ove šeste faze je veoma jednostavan: **Trenirati model od nule**. Za ovo će se koristiti prethodna LLM architecture, uz petlje koje prolaze kroz skupove podataka i koriste definisane loss functions i optimizer za treniranje svih parametara modela.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> LoRA značajno smanjuje broj trainable parameters i stanje optimizer-a potrebno za fine-tuning pretrained modela.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> Cilj ovog odeljka je da pokaže kako se već pretrained model može fine-tune-ovati tako da, umesto generisanja novog teksta, LLM **navede verovatnoće da dati tekst pripada svakoj od datih kategorija** (na primer, da li je tekst spam ili nije).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> Cilj ovog odeljka je da pokaže kako se već pretrained model može **fine-tune-ovati tako da prati instrukcije**, umesto da samo generiše tekst, na primer, odgovaranjem na zadatke kao chatbot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
