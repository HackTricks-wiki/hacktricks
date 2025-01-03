# PDF File analysis

{{#include ../../../banners/hacktricks-training.md}}

**Kwa maelezo zaidi angalia:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Muundo wa PDF unajulikana kwa ugumu wake na uwezo wa kuficha data, na kufanya kuwa kitovu cha changamoto za forensics za CTF. Unachanganya vipengele vya maandiko ya kawaida na vitu vya binary, ambavyo vinaweza kuwa vimefinywa au kufichwa, na vinaweza kujumuisha skripti katika lugha kama JavaScript au Flash. Ili kuelewa muundo wa PDF, mtu anaweza kurejelea [nyenzo za utangulizi](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) za Didier Stevens, au kutumia zana kama mhariri wa maandiko au mhariri maalum wa PDF kama Origami.

Kwa uchunguzi wa kina au usimamizi wa PDFs, zana kama [qpdf](https://github.com/qpdf/qpdf) na [Origami](https://github.com/mobmewireless/origami-pdf) zinapatikana. Data zilizofichwa ndani ya PDFs zinaweza kufichwa katika:

- Tabaka zisizoonekana
- Muundo wa metadata wa XMP na Adobe
- Vizazi vya ongezeko
- Maandishi yenye rangi sawa na ya nyuma
- Maandishi nyuma ya picha au picha zinazovutana
- Maoni yasiyoonyeshwa

Kwa uchambuzi wa PDF wa kawaida, maktaba za Python kama [PeepDF](https://github.com/jesparza/peepdf) zinaweza kutumika kuunda skripti za uchambuzi maalum. Zaidi, uwezo wa PDF wa kuhifadhi data zilizofichwa ni mkubwa kiasi kwamba rasilimali kama mwongozo wa NSA kuhusu hatari za PDF na hatua za kupambana, ingawa haupo tena kwenye eneo lake la awali, bado unatoa maarifa muhimu. [Nakala ya mwongozo](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1s/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) na mkusanyiko wa [hila za muundo wa PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) kutoka kwa Ange Albertini zinaweza kutoa kusoma zaidi juu ya mada hiyo.

{{#include ../../../banners/hacktricks-training.md}}
