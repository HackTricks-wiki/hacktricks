# Mafunzo ya LLM - Maandalizi ya Data

{{#include ../../banners/hacktricks-training.md}}

**Haya ni maelezo yangu kutoka kwenye kitabu kinachopendekezwa sana** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **pamoja na maelezo ya ziada.**<sup>[[1]](#references)</sup>

## Maelezo ya Msingi

Unapaswa kuanza kwa kusoma chapisho hili kuhusu dhana za msingi unazopaswa kuzifahamu:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> Lengo la awamu hii ni **kugawanya ingizo kuwa tokens na kuzipangia token IDs**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Usampulishaji wa Data

> [!TIP]
> Lengo la awamu hii ni kuandaa mfuatano wa mafunzo wenye urefu wa context uliochaguliwa, pamoja na malengo yao ya utabiri yaliyosogezwa.


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> Lengo la awamu hii ya tatu ni rahisi sana: **Kupa kila token ya awali katika vocabulary vector yenye vipimo vinavyohitajika ili kufunza model.** Kila neno katika vocabulary litakuwa nukta katika space yenye vipimo X.\
> Kumbuka kuwa mwanzoni, nafasi ya kila neno katika space huanzishwa tu kwa njia ya "random", na nafasi hizi ni trainable parameters (zitaboreshwa wakati wa mafunzo).
>
> Zaidi ya hayo, wakati wa token embedding, **embedding layer nyingine huundwa** ambayo inawakilisha (katika hali hii) **nafasi kamili ya neno katika sentensi ya mafunzo**. Kwa njia hii, neno lililo katika nafasi tofauti katika sentensi huwa na representation tofauti.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> Lengo la awamu hii ya nne ni rahisi sana: **Kutumia baadhi ya attention mechanisms**. Hizi zitakuwa **layers zinazorudiwa mara nyingi** ambazo **zitakamata uhusiano kati ya neno katika vocabulary na majirani zake katika sentensi ya sasa inayotumika kufunza LLM**.\
> Layers nyingi hutumika kwa ajili hii, hivyo trainable parameters nyingi zitakuwa zikikamata taarifa hii.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> Lengo la awamu hii ya tano ni rahisi sana: **Kutengeneza architecture kamili ya LLM**. Weka kila kitu pamoja, tumia layers zote na uunde functions zote za kuzalisha text au kubadilisha text kuwa IDs na kurudi kinyume.
>
> Architecture hii itatumika kwa mafunzo na kwa kutabiri text baada ya kufunzwa.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> Lengo la awamu hii ya sita ni rahisi sana: **Kufunza model kutoka mwanzo**. Kwa ajili hii, architecture ya awali ya LLM itatumika pamoja na loops zinazopitia data sets kwa kutumia loss functions na optimizer zilizofafanuliwa ili kufunza parameters zote za model.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. Maboresho ya LoRA katika fine-tuning

> [!TIP]
> LoRA hupunguza kwa kiasi kikubwa idadi ya trainable parameters na optimizer state inayohitajika kufanya fine-tune ya model iliyofunzwa awali.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning kwa Classification

> [!TIP]
> Lengo la sehemu hii ni kuonyesha jinsi ya kufanya fine-tune ya model iliyokwisha pre-trained ili badala ya kuzalisha text mpya, LLM itoe **probabilities za text iliyotolewa kuainishwa katika kila moja ya categories zilizotolewa** (kwa mfano, kama text ni spam au la).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning ili kufuata instructions

> [!TIP]
> Lengo la sehemu hii ni kuonyesha jinsi ya **kufanya fine-tune ya model iliyokwisha pre-trained ili ifuate instructions** badala ya kuzalisha text tu, kwa mfano, kujibu tasks kama chat bot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
