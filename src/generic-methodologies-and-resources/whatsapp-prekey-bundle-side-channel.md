# Upungufu na Kujazwa Upya kwa Kifurushi cha Prekey cha WhatsApp: Side Channel

{{#include ../banners/hacktricks-training.md}}

WhatsApp huhifadhi identity key, signed prekey na akiba ya one-time prekeys kwa kila kifaa. Kupakua bundle ya kifaa hutumia one-time prekey moja iliyohifadhiwa kwenye server, hata kama anayeomba hatumi ujumbe wowote. Hii humpa mshambuliaji mwenye akaunti ya WhatsApp na nambari ya simu ya mlengwa njia ya kuchunguza **upande wa server**, tofauti na [muda wa delivery receipt upande wa client](side-channel-attacks-on-messaging-protocols.md). Kukosekana kwa one-time prekey pia hudhoofisha forward secrecy kwa ujumbe *wa awali* wa session mpya; lakini hakufichui plaintext peke yake.<sup>[[1]](#references)[[2]](#references)</sup>

## Kagua bundle za vifaa vya mlengwa

[Prekey Pogo artifact](https://github.com/sbaresearch/prekey-pogo) huunganishwa kama session saidizi ya WhatsApp na inaunga mkono maswali ya **kufanywa kwa mikono** kuhusu vifaa na prekey. Iunganishe na akaunti ya majaribio, kisha tumia amri zake shirikishi za `target`, `devices`, `prekey` (kifaa kikuu) na `combine` (vifaa vyote). Artifact iliyotolewa imeacha kwa makusudi vitendaji vya depletion ya kiotomatiki na kusababisha msongamano kwenye server.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

Kwa kila jibu, rekodi JID ya kifaa, timestamp ya bundle `t`, ID ya signed-prekey `skey.id`, na kama one-time `key.id` ipo. Device ID `0` ni simu; ID zisizo `0` ni vifaa vya ziada. Katika implementations zilizojaribiwa kwenye paper, ID ya awali ya signed-prekey pia hutofautisha baadhi ya clients: Android huanza na `0`, iOS na macOS hutumia thamani nasibu, na WhatsApp Web na Windows Desktop huanza na `1`. Ichukulie hii kama alama ya kutambua implementation, si kanuni ya protocol isiyobadilika.<sup>[[1]](#references)</sup>

## Geuza ujazaji upya wa key kuwa oracle ya hali ya mtandaoni

Kwanza, fanya calibration kwenye kifaa unachodhibiti: omba bundle yake mara kwa mara hadi server iache kurudisha one-time `key`, huku ukirekodi timestamp na ID za key za mwisho. Kwa kifaa lengwa, rudia upunguzaji huo kisha uulize tena baada ya muda uliodhibitiwa: one-time key mpya na timestamp ya bundle iliyosonga mbele vinaonyesha kuwa kifaa kilipakia batch mpya. Katika majaribio ya WhatsApp yaliyoripotiwa, server ilichochea ujazaji upya wakati key zisizozidi 11 zilikuwa zimesalia, na clients zilipakia key mpya 812. Tumia utaratibu huu kwa kila device JID ili kutofautisha simu na vifaa vya ziada. Ucheleweshaji wa ujazaji upya **unaashiria tu** kwamba kifaa kiko offline: upangaji wa kazi za chinichini, kukatika kwa mtandao na ucheleweshaji wa ujazaji upya unaotegemea client vinaweza kusababisha hali hiyo hiyo. Tofauti na RTT ya receipt, uchunguzi huu hauhitaji ciphertext iliyowasilishwa wala acknowledgment kutoka upande wa mwathiriwa.<sup>[[1]](#references)[[2]](#references)</sup>

Kila query hutumia one-time key, kwa hivyo oracle ya muda mrefu inahitaji custom client inayoweza kurudia upatikanaji wa prekey; artifact ya umma inaonyesha tu queries za mikono. Kuacha akiba ikiwa tupu kunaweza kusababisha watumiaji wengine kuanzisha sessions mpya bila one-time prekey. Hilo hupunguza forward secrecy ya ujumbe wa awali hadi hatua mpya ya ratchet, lakini kutumia ciphertext iliyorekodiwa kunahitaji pia ufikiaji wa ciphertext ya E2EE na baadaye kuathiriwa kwa private keys husika za muda mrefu na za muda wa kati. Sessions zilizopo na zilizoanzishwa hazishushwi kiwango moja kwa moja.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo: Kuchunguza Masuala ya Usalama na Faragha katika Utaratibu wa Handshake wa WhatsApp](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [Itifaki ya Makubaliano ya Key ya X3DH](https://signal.org/docs/specifications/x3dh/)
- [3] [Artifacts za Prekey Pogo](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}
