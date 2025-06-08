# LLM Trening - Priprema Podataka

**Ovo su moje beleške iz veoma preporučene knjige** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **sa dodatnim informacijama.**

## Osnovne Informacije

Trebalo bi da počnete čitanjem ovog posta za neke osnovne koncepte koje treba da znate:

{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenizacija

> [!TIP]
> Cilj ove inicijalne faze je veoma jednostavan: **Podeliti ulaz u tokene (ids) na način koji ima smisla**.

{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Uzorkovanje Podataka

> [!TIP]
> Cilj ove druge faze je veoma jednostavan: **Uzorkovati ulazne podatke i pripremiti ih za fazu obuke obično razdvajanjem skupa podataka na rečenice određene dužine i generisanjem očekivanog odgovora.**

{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Umetanja

> [!TIP]
> Cilj ove treće faze je veoma jednostavan: **Dodeliti svakom od prethodnih tokena u rečniku vektor željenih dimenzija za obuku modela.** Svaka reč u rečniku će biti tačka u prostoru X dimenzija.\
> Imajte na umu da je inicijalno pozicija svake reči u prostoru samo "nasumično" inicijalizovana i te pozicije su parametri koji se mogu obučavati (biće poboljšani tokom obuke).
>
> Štaviše, tokom umetanja tokena **stvara se još jedan sloj umetanja** koji predstavlja (u ovom slučaju) **apsolutnu poziciju reči u rečenici za obuku**. Na ovaj način, reč na različitim pozicijama u rečenici će imati različitu reprezentaciju (značenje).

{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Mehanizmi Pažnje

> [!TIP]
> Cilj ove četvrte faze je veoma jednostavan: **Primena nekih mehanizama pažnje**. Ovi će biti mnogo **ponovljenih slojeva** koji će **uhvatiti odnos reči u rečniku sa njenim susedima u trenutnoj rečenici koja se koristi za obuku LLM-a**.\
> Za ovo se koristi mnogo slojeva, tako da će mnogo parametara koji se mogu obučavati uhvatiti ove informacije.

{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Arhitektura

> [!TIP]
> Cilj ove pete faze je veoma jednostavan: **Razviti arhitekturu celog LLM-a**. Spojiti sve, primeniti sve slojeve i kreirati sve funkcije za generisanje teksta ili transformaciju teksta u ID-ove i obrnuto.
>
> Ova arhitektura će se koristiti i za obuku i za predikciju teksta nakon što je obučena.

{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Predobuka i Učitavanje modela

> [!TIP]
> Cilj ove šeste faze je veoma jednostavan: **Obučiti model od nule**. Za ovo će se koristiti prethodna LLM arhitektura sa nekim petljama koje prolaze kroz skupove podataka koristeći definisane funkcije gubitka i optimizator za obuku svih parametara modela.

{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Poboljšanja u finom podešavanju

> [!TIP]
> Korišćenje **LoRA značajno smanjuje računarske resurse** potrebne za **fino podešavanje** već obučenih modela.

{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fino Podešavanje za Klasifikaciju

> [!TIP]
> Cilj ovog odeljka je da pokaže kako fino podešavati već obučeni model tako da umesto generisanja novog teksta LLM daje **verovatnoće da dati tekst bude kategorizovan u svaku od datih kategorija** (kao što je da li je tekst spam ili ne).

{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fino Podešavanje za Praćenje Uputstava

> [!TIP]
> Cilj ovog odeljka je da pokaže kako **fino podešavati već obučeni model da prati uputstva** umesto samo generisanja teksta, na primer, odgovaranje na zadatke kao chat bot.

{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}
