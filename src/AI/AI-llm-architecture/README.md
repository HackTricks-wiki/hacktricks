# Mafunzo ya LLM - Maandalizi ya Data

{{#include ../../banners/hacktricks-training.md}}

**Haya ni maelezo yangu kutoka kwenye kitabu kinachopendekezwa sana** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **pamoja na maelezo ya ziada.**<sup>[[1]](#references)</sup>

## Taarifa za Msingi

Unapaswa kuanza kwa kusoma chapisho hili kuhusu dhana za msingi unazopaswa kuzifahamu:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> Lengo la awamu hii ya awali ni rahisi sana: **Gawanya input kuwa tokens (ids) kwa namna yenye mantiki**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> Lengo la awamu hii ya pili ni rahisi sana: **Chukua sampuli za input data na uitayarishe kwa awamu ya training, kwa kawaida kwa kugawanya dataset kuwa sentensi zenye urefu maalum na pia kutengeneza jibu linalotarajiwa.**


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> Lengo la awamu hii ya tatu ni rahisi sana: **Wape kila token ya awali katika vocabulary vector yenye dimensions zinazohitajika ili ku-train model.** Kila neno katika vocabulary litakuwa pointi katika space yenye dimensions X.\
> Kumbuka kuwa mwanzoni nafasi ya kila neno katika space huanzishwa kwa njia ya "random" na nafasi hizi ni trainable parameters (zitaboreshwa wakati wa training).
>
> Zaidi ya hayo, wakati wa token embedding **layer nyingine ya embeddings huundwa** ambayo inawakilisha (katika hali hii) **nafasi ya absolute ya neno katika training sentence**. Kwa njia hii, neno lililo katika nafasi tofauti katika sentence litakuwa na representation (maana) tofauti.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> Lengo la awamu hii ya nne ni rahisi sana: **Tumia attention mechanisms**. Hizi zitakuwa **layers nyingi zinazojirudia** ambazo **zitakamata uhusiano wa neno katika vocabulary na majirani zake katika sentence ya sasa inayotumika ku-train LLM**.\
> Layers nyingi hutumika kwa ajili hii, hivyo trainable parameters nyingi zitakamata taarifa hii.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> Lengo la awamu hii ya tano ni rahisi sana: **Tengeneza architecture ya LLM kamili**. Unganisha kila kitu, tumia layers zote na uunde functions zote za kuzalisha text au kubadilisha text kuwa IDs na kinyume chake.
>
> Architecture hii itatumika kwa training na pia kwa predicting text baada ya model ku-trainiwa.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> Lengo la awamu hii ya sita ni rahisi sana: **Train model kutoka mwanzo**. Kwa ajili hii, architecture ya awali ya LLM itatumika pamoja na loops zinazopitia data sets kwa kutumia loss functions na optimizer zilizofafanuliwa ili ku-train parameters zote za model.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> Matumizi ya **LoRA hupunguza sana computation** inayohitajika ili **fine-tune** models ambazo tayari zime-trainiwa.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> Lengo la sehemu hii ni kuonyesha jinsi ya kufanya fine-tune model ambayo tayari ime-pre-trainiwa ili badala ya kuzalisha text mpya, LLM itoe **probabilities za text iliyotolewa kuainishwa katika kila mojawapo ya categories zilizotolewa** (kwa mfano, ikiwa text ni spam au la).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> Lengo la sehemu hii ni kuonyesha jinsi ya **kufanya fine-tune model ambayo tayari ime-pre-trainiwa ili ifuate instructions** badala ya kuzalisha text tu, kwa mfano, kujibu tasks kama chat bot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## Marejeo

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)

{{#include ../../banners/hacktricks-training.md}}
