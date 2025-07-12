# LLM Training - Data Preparation

{{#include ../../banners/hacktricks-training.md}}

**Hizi ni nota zangu kutoka kwa kitabu kinachopendekezwa sana** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **pamoja na taarifa za ziada.**

## Basic Information

Unapaswa kuanza kwa kusoma chapisho hili kwa baadhi ya dhana za msingi unazopaswa kujua kuhusu:

{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> Lengo la awamu hii ya awali ni rahisi sana: **Gawanya ingizo katika token (ids) kwa njia ambayo ina maana**.

{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> Lengo la awamu hii ya pili ni rahisi sana: **Chukua sampuli ya data ya ingizo na kuandaa kwa awamu ya mafunzo kwa kawaida kwa kutenganisha dataset katika sentensi za urefu maalum na pia kuzalisha jibu linalotarajiwa.**

{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> Lengo la awamu hii ya tatu ni rahisi sana: **Patia kila moja ya token zilizopita katika msamiati vector ya vipimo vinavyotakiwa ili kufundisha mfano.** Kila neno katika msamiati litakuwa na pointi katika nafasi ya vipimo X.\
> Kumbuka kwamba awali nafasi ya kila neno katika nafasi inaanzishwa "kwa bahati nasibu" na nafasi hizi ni vigezo vinavyoweza kufundishwa (vitaboreshwa wakati wa mafunzo).
>
> Zaidi ya hayo, wakati wa token embedding **tabaka lingine la embeddings linaundwa** ambalo linawakilisha (katika kesi hii) **nafasi halisi ya neno katika sentensi ya mafunzo**. Kwa njia hii neno katika nafasi tofauti katika sentensi litakuwa na uwakilishi tofauti (maana).

{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> Lengo la awamu hii ya nne ni rahisi sana: **Tumia baadhi ya mitambo ya umakini**. Hizi zitakuwa tabaka nyingi **zinazorudiwa** ambazo zitakuwa **zinakamata uhusiano wa neno katika msamiati na majirani zake katika sentensi ya sasa inayotumika kufundisha LLM**.\
> Tabaka nyingi zinatumika kwa hili, hivyo vigezo vingi vinavyoweza kufundishwa vitakuwa vinakamata taarifa hii.

{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> Lengo la awamu hii ya tano ni rahisi sana: **Tengeneza muundo wa LLM kamili**. Panga kila kitu pamoja, tumia tabaka zote na uunde kazi zote za kuzalisha maandiko au kubadilisha maandiko kuwa IDs na kinyume chake.
>
> Muundo huu utatumika kwa mafunzo na kutabiri maandiko baada ya kufundishwa.

{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> Lengo la awamu hii ya sita ni rahisi sana: **Fundisha mfano kutoka mwanzo**. Kwa hili muundo wa awali wa LLM utatumika na miduara fulani ikipita juu ya seti za data kwa kutumia kazi zilizofafanuliwa za kupoteza na optimizer ili kufundisha vigezo vyote vya mfano.

{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> Matumizi ya **LoRA hupunguza sana hesabu** inayohitajika ili **kurekebisha** mifano iliyofundishwa tayari.

{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> Lengo la sehemu hii ni kuonyesha jinsi ya kurekebisha mfano uliofundishwa tayari ili badala ya kuzalisha maandiko mapya LLM itachagua kutoa **uwezekano wa maandiko yaliyotolewa kuainishwa katika kila moja ya makundi yaliyotolewa** (kama maandiko ni spam au la).

{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> Lengo la sehemu hii ni kuonyesha jinsi ya **kurekebisha mfano uliofundishwa tayari ili kufuata maagizo** badala ya tu kuzalisha maandiko, kwa mfano, kujibu kazi kama roboti ya mazungumzo.

{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
