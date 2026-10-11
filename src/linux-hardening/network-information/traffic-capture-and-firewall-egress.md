# Uchunguzi wa Trafiki, Firewall na Trafiki Inayotoka

{{#include ../../banners/hacktricks-training.md}}

Baada ya kupata [huduma zinazosikiliza za ndani na soketi za Unix](local-network-and-socket-triage.md), kagua ni violesura vipi vinavyobeba trafiki yake na ni sheria zipi za firewall au proxy zinazoathiri ufikiaji wake. Huduma inayopatikana kupitia loopback pekee inaweza kubeba vichwa nyeti vya HTTP hata ikiwa haipatikani kutoka kwa mashine nyingine.

## Kagua ruhusa za kunasa trafiki na uchague kiolesura

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` inaweza kuwa na uwezo wa kunasa pakiti hata kama mtumiaji wa sasa hana ufikiaji wa sudo. Kagua uwezo halisi wa kitekelezaji na ruhusa za kikundi. Nasa kwenye kiolesura kinachofaa zaidi, kwa muda mfupi iwezekanavyo na kwa kichujio; unasa unaweza kuwa na vitambulisho vya kuingia au data binafsi.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` huunda upya mitiririko ya TCP ya maandishi wazi; `tshark` inaweza kuchuja na kutoa sehemu kutoka kwenye capture. Kwa trafiki ya TLS, usimbuaji unahitaji funguo za endpoint au client inayotumika iliyosanidiwa kwa `SSLKEYLOGFILE` kabla ya muunganisho. [Ukurasa wa uchunguzi wa awali wa mtandao wa ndani](local-network-and-socket-triage.md#tls-key-logging) unaonyesha utaratibu huo. Usichukulie capture iliyosimbwa kuwa maandishi wazi yanayosomeka.

Artifacts za tukio zilizohifadhiwa zinaweza kubadilisha tathmini hiyo. [Linux core dump ni picha ya kumbukumbu ya mchakato](https://man7.org/linux/man-pages/man5/core.5.html), ambayo inaweza kuhifadhi session key; ikiwa dump inayosomeka na packet capture zilitoka kwenye mchakato na session ileile, mchambuzi anaweza kuweza kusimbua trafiki hiyo. Kwanza orodhesha njia na ruhusa za artifacts, kisha uthibitishe kando utambulisho wa mchakato, muda wa capture, protocol na umbizo la key. Trafiki iliyosimbuliwa au archive iliyorejeshwa ni kidokezo cha ufichuaji, si uthibitisho wa ufikiaji wa akaunti nyingine: nyenzo yoyote ya sehemu ya SSH key bado inahitaji kuunganishwa upya, kulinganishwa na public key inayolingana, na kukubaliwa na sera ya SSH ya akaunti hiyo. Epuka kuonyesha maudhui ya core au payload za capture kwenye matokeo mapana ya uorodheshaji.

## Tambua tabaka za firewall

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` na `iptables` zinaweza kufikiwa kupitia vifungashio vya usambazaji kama UFW au firewalld. Soma sheria zinazotumika na usanidi uliohifadhiwa wa kifungashio; sheria inayoonekana katika uwakilishaji mmoja huenda ilitengenezwa na zana nyingine. Kagua kiolesura, mwelekeo, chanzo, lengwa, itifaki, porti na hali ya muunganisho kabla ya kuhusisha huduma iliyozuiwa na sheria fulani. Tazama [ukaguzi wa sheria za nftables](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) kwa mfano mahususi.

## Jaribu egress na tabia ya proxy

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Tenganisha hitilafu ya DNS na hitilafu ya TCP, TLS au proxy. Jaribu lengwa na itifaki mahususi zinazohusika na tathmini; kufikiwa kupitia ICMP hakumaanishi kuwa TCP au UDP zimeruhusiwa. Ikiwa proxy imesanidiwa, linganisha ombi lililokusudiwa kupitia proxy na ombi kwa lengwa hilohilo chini ya sheria husika za `no_proxy`. Port forward ya ndani inaweza pia kufanya huduma ya loopback ipatikane mahali pengine, kwa hivyo kagua listeners zinazotumika na SSH tunnels wakati hali ya firewall na ufichuaji unaoonekana havilingani.
{{#include ../../banners/hacktricks-training.md}}
