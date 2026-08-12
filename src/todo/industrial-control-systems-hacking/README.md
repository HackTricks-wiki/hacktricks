# Udukuzi wa Mifumo ya Udhibiti wa Viwanda

{{#include ../../banners/hacktricks-training.md}}

## Kuhusu Sehemu Hii

Sehemu hii inatambulisha vipengele, usanifu, protocols, na mbinu za security-assessment za industrial control system (ICS). ICS ni sehemu ya kikoa kipana cha operational technology (OT): mifumo na vifaa vinavyoweza kuprogramiwa ambavyo hufuatilia au kusababisha mabadiliko katika michakato ya kimwili. Mifano ya kawaida ni pamoja na mifumo ya supervisory control and data acquisition (SCADA), distributed control systems (DCSs), na programmable logic controllers (PLCs).<sup>[[1]](#references)</sup>

Kazi ya security katika mazingira haya lazima izingatie mahitaji yanayotofautiana na IT ya kawaida, ikiwa ni pamoja na usalama wa mchakato, reliability, availability, uendeshaji wa deterministic, na mizunguko ya maisha ya vifaa. Security control inayokubalika kitaalamu bado inaweza kuwa isiyofaa ikiwa itavuruga mchakato wa kimwili, kwa hivyo testing na remediation zinapaswa kuratibiwa na mmiliki wa mfumo pamoja na wafanyakazi wa operations.<sup>[[1]](#references)</sup>

Kuhatarishwa kwa mfumo au kuvurugwa kwa bahati mbaya kunaweza kusimamisha uzalishaji, kuharibu vifaa, kuachilia nyenzo hatari, kuathiri mazingira, au kusababisha majeraha na vifo. Uwezekano huu wa athari za kimwili ndio sababu uelewa wa mchakato unaodhibitiwa na mipaka yake salama ya uendeshaji lazima utangulie active testing.<sup>[[1]](#references)</sup>

Deployments nyingi za OT bado zinatumia operating systems, applications, na protocols za zamani kwa sababu vifaa vina maisha marefu ya huduma na mabadiliko yanahitaji testing ya kiutendaji na kiusalama. Baadhi ya protocols ziliundwa bila authentication au encryption ya kisasa, na patching inaweza kuzuiwa na vendor support au maintenance windows; tumia segmentation, access control, na monitoring kama upgrades za moja kwa moja haziwezekani.<sup>[[1]](#references)</sup>

## Vipaumbele vya Assessment

Anza kwa kuelewa mchakato unaodhibitiwa, mipaka ya mfumo, network topology, assets, data flows, trust relationships, na connections za nje. Aina zinazofanana za vifaa zinaweza kutekeleza majukumu tofauti katika sites mbalimbali, kwa hivyo epuka kudhani kwamba usanifu au model ya athari ya deployment moja inatumika kwa nyingine.<sup>[[1]](#references)</sup>

Pendelea passive discovery na nyaraka zilizopo za engineering inapowezekana. Active scanning au exploitation yoyote inapaswa kufuata mpango wa testing ulioidhinishwa unaofafanua vikwazo vya usalama, maintenance windows, recovery procedures, na stop conditions. Findings zinapaswa kutathminiwa kwa kuzingatia athari za cybersecurity pamoja na madhara yanayoweza kutokea kwa mchakato wa kimwili.<sup>[[1]](#references)</sup>

Ujuzi huo huo wa usanifu unaunga mkono shughuli za defensive kama vile asset inventory, network segmentation, monitoring, incident response, na risk-based vulnerability management.<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Mwongozo wa Security ya Operational Technology (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
