# Open vSwitch में forwarded-skb marker हटाकर ESP page-cache में writes

{{#include ../../../banners/hacktricks-training.md}}

Linux kernel exploitation का एक उपयोगी pattern है **skb से ownership metadata हटाना, लेकिन उसके foreign fragments को बरकरार रखना**, और फिर उस skb को ऐसे consumer तक भेजना जो in place लिखता हो। Open vSwitch (OVS) के मामले में, userspace upcall विफल होने पर एक जीवित `MSG_ZEROCOPY` skb से `SKBFL_SHARED_FRAG` clear हो जाता है; इसके बाद ESP सीधे read-only file के page-cache folio पर decrypt करता है। इससे page cache में एक deterministic local write होता है। इसे CVE-2026-90049, CVE-2026-89487 और CVE-2026-80977 के तहत track किया गया है।<sup>[[1]](#references)[[2]](#references)</sup>

यह classic memory corruption के बजाय Copy Fail/Dirty Frag-class issue है: इसमें race या address disclosure की आवश्यकता नहीं होती, file का केवल readable होना जरूरी है, और बदले हुए bytes disk पर नहीं, बल्कि page cache में मौजूद होते हैं।<sup>[[2]](#references)[[3]](#references)</sup>

## Security invariant: foreign fragments पर marker बना रहना चाहिए

`SKBFL_SHARED_FRAG` in-place consumers को बताता है कि skb fragment ऐसे storage को refer कर सकता है जिसका वे निजी तौर पर स्वामित्व नहीं रखते। `esp_input()` में ESP fast path किसी nonlinear, uncloned skb को in place तभी decrypt कर सकता है जब `skb_has_shared_frag()` false हो; अन्यथा `skb_cow_data()` पहले private storage बनाता है। यह consumer-side check Dirty Frag के बाद जोड़ा गया था।<sup>[[5]](#references)</sup>

इसलिए invariant के दो स्वतंत्र हिस्से हैं:<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. In-place writers को `SKBFL_SHARED_FRAG` जांचना चाहिए और mutation से पहले shared data की copy बनानी चाहिए।
2. हर clone, coalesce, transfer या forwarding path को तब तक marker बनाए रखना चाहिए, जब तक foreign page जुड़ा रहे।

`skb_try_coalesce()` में fragment descriptors को move करते समय Fragnesia ने दूसरे नियम का उल्लंघन किया। OVS path थोड़ा अलग है: यह fragment को transfer ही नहीं करता; यह **मूल skb पर in place marker clear करता है और फिर उसे forward करना जारी रखता है**।<sup>[[2]](#references)[[4]](#references)</sup>

## Unprivileged OVS तक पहुंच

OVS का kernel datapath `ovs_datapath`, `ovs_vport`, `ovs_flow` और `ovs_packet` जैसे generic-netlink families के जरिए नियंत्रित होता है। इसके mutating operations namespace-aware `GENL_UNS_ADMIN_PERM` का उपयोग करते हैं, इसलिए `unshare -Urn` के तहत चल रही process अपने network namespace में datapath बनाने, veth जोड़ने और flow actions install करने के लिए आवश्यक `CAP_NET_ADMIN` प्राप्त कर सकती है। OVS family को resolve करने से `openvswitch.ko` autoload भी हो सकता है; इस attack surface के लिए host `CAP_SYS_MODULE`, `ovs-vsctl` या `ovs-vswitchd` की आवश्यकता नहीं है।<sup>[[2]](#references)[[7]](#references)</sup>

दो upcall types के बीच का अंतर महत्वपूर्ण है:<sup>[[2]](#references)[[7]](#references)</sup>

- **Flow miss** packet को `ovs-vswitchd` तक भेजता है; upcall विफल होने पर packet सामान्यतः drop हो जाता है।
- Explicit `OVS_ACTION_ATTR_USERSPACE` action एक borrowed copy को चुने हुए port ID तक भेजता है, फिर मूल skb पर बाद के actions execute करता है।

इसलिए attacker इस तरह का flow install कर सकता है:<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

चुने गए port ID का कोई listener स्वामी नहीं है, इसलिए userspace action अपेक्षित रूप से विफल होती है, जबकि अगली `OUTPUT` action मूल packet को जीवित रखती है।<sup>[[1]](#references)[[2]](#references)</sup>

## मूल कारण: जीवित रहने वाले packet पर `skb_tx_error()`

कमज़ोर OVS upcall error path `skb_tx_error(skb)` को call करता है। यह helper ऐसे विफल transmit के लिए बनाया गया था जिसके बाद skb को free कर दिया जाता है; यह `skb_zcopy_clear()` के ज़रिए zerocopy bookkeeping पूरी करता है, जिसके flag mask से ऐतिहासिक रूप से `SKBFL_SHARED_FRAG` भी हट जाता था। OVS ने userspace-action error को अनदेखा किया और अपनी action list जारी रखी, जिससे helper के lifetime contract का उल्लंघन हुआ।<sup>[[1]](#references)[[2]](#references)</sup>

यह exploit की जा सकने वाली state transition है:<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

यह तभी काम करता है जब `skb_zcopy()` को zerocopy state मिलता है। केवल `SKBFL_SHARED_FRAG` वाला fragment पर्याप्त नहीं है; `MSG_ZEROCOPY` उपयोगी है क्योंकि यह `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG` बनाता है और `SKBFL_DONT_ORPHAN` भी सेट करता है। इस flag के कारण OVS userspace copy के दौरान `skb_orphan_frags()` foreign pages को बदलने से चूक जाता है।<sup>[[2]](#references)[[3]](#references)</sup>

## write primitive बनाना

End-to-end trigger में ये घटक शामिल हैं।<sup>[[2]](#references)[[3]](#references)</sup>

1. `unshare -Urn` से private user और network namespaces में प्रवेश करें।
2. `PROT_READ | MAP_SHARED` के साथ target file को map करें।
3. अलग sender netns और veth pair का उपयोग करें; local loopback borrowed pages की copy बना देगा और primitive को नष्ट कर देगा।
4. OVS datapath और विफल होने वाला `USERSPACE`-then-`OUTPUT` flow बनाएं।
5. `rfc4106(gcm(aes))` और UDP port 4500 का उपयोग करके transport-mode ESP-in-UDP XFRM state इंस्टॉल करें।
6. `[ESP header | mapped file bytes | invalid ICV]` के आकार वाले iovec के साथ एक `MSG_ZEROCOPY` datagram भेजें।

XFRM state में AES-128-GCM का 20-byte keying material होता है: 16-byte AES key, जिसके बाद चार-byte RFC 4106 salt आता है। चुने गए आठ-byte explicit IV के लिए, payload confidentiality की शुरुआत counter block `salt || IV || be32(2)` से होती है; counter value 1 इसके बजाय authentication result को mask करता है।<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

एक बार OVS marker को हटा देता है, तो ESP अपना no-copy path लेता है और file-backed fragment पर `plaintext = ciphertext XOR keystream` लागू करता है। Authentication की जाँच इस transform के **बाद** होती है, इसलिए all-zero invalid ICV के कारण packet `-EBADMSG` के साथ तभी fail होता है, जब page-cache bytes पहले ही बदल चुके होते हैं।<sup>[[2]](#references)</sup>

### GCM को चुने हुए bytes में बदलना

वर्तमान byte `C` और वांछित byte `P` के लिए, पहले payload keystream byte का मान `C XOR P` होना चाहिए। AES key और salt को स्थिर रखते हुए, explicit IV के 16-bit suffix को sweep करें और हर संभावित पहले keystream byte के लिए एक suffix पहले से compute करें:<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

सार्वजनिक implementation ciphertext को 32 bytes तक सीमित करता है और हर packet के लिए file fragment को एक byte आगे बढ़ाता है। चुना गया पहला byte पिछले packet के पहले collateral byte को overwrite करता है; हर packet से पहले `pread()` `C` को refresh करता है, समान bytes छोड़ दिए जाते हैं, और अंतिम packet को छोटा किया जाता है ताकि writes अनुरोधित range से आगे न जाएँ। इस तरह, 256-entry lookup table इस primitive को byte-granular chosen-content page-cache write में बदल देती है, जिसमें हर अलग byte के लिए लगभग एक packet लगता है।<sup>[[2]](#references)[[3]](#references)</sup>

## Page-cache write से root तक

एक व्यावहारिक target, पहले से मौजूद setuid-root executable है। PoC पहले 160 bytes को एक complete static ELF से बदलता है, जिसमें एक fixed-address read/execute `PT_LOAD`, कोई `PT_INTERP` नहीं, और ऐसा code होता है जो `execve("/bin/sh", ...)` से पहले `setuid(0)` call करता है। इससे original binary के entry point, PIE layout, dynamic loader या relocations के बारे में धारणाएँ बनाने की ज़रूरत नहीं पड़ती।<sup>[[2]](#references)[[3]](#references)</sup>

बदला हुआ content user namespaces में भी दिखता है, क्योंकि page cache namespaces के अधीन नहीं है। बदले हुए folio को dirty के रूप में mark नहीं किया जाता, इसलिए उसे वापस disk पर नहीं लिखा जाता; target को resident रहते हुए execute करें, फिर `posix_fadvise(..., POSIX_FADV_DONTNEED)` से अस्थायी corruption को discard करें, ताकि बाद में पढ़ने पर disk का मूल content reload हो।<sup>[[2]](#references)[[3]](#references)</sup>

## Exposure की जाँच और mitigation

पहले वास्तविक vendor kernel की जाँच करें। Exposure के लिए प्रासंगिक शर्तें हैं unprivileged user namespaces, OVS की उपलब्धता या उसका resident होना, और ESP implementation की उपलब्धता।<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

पूरी fix series वाले kernel पर upgrade करें; अंतिम repair recirculation path को भी कवर करता है और shared `skb_shinfo()` state को mutate करने से बचता है, साथ ही `skb_zerocopy()` में संबंधित strip को भी बंद करता है।<sup>[[1]](#references)[[2]](#references)</sup>

अगर OVS का उपयोग नहीं होता है, तो केवल `blacklist` पर निर्भर रहने के बजाय modprobe `install` rule से alias और by-name दोनों loading रोकें। अगर host IPsec terminate नहीं करता है और ESP modular है, तो इसी control से decrypt sink को भी हटाया जा सकता है।<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

ये नियम तब मदद नहीं करते जब कोई module पहले से loaded हो या feature kernel में built-in हो। Unprivileged user namespaces को disable करने से namespace capability का स्रोत भी हट जाता है, लेकिन इससे browsers, Flatpak, Podman और अन्य sandboxing/container workloads प्रभावित हो सकते हैं।<sup>[[2]](#references)</sup>

## समीक्षा से मिले सबक

Zero-copy networking का audit करते समय, खोज को केवल उन helpers तक सीमित न रखें जो fragments को copy या move करते हैं। उन error/completion helpers की भी पहचान करें जो grouped flags को clear करते हैं, और फिर सत्यापित करें कि हर caller, skb lifetime के documented contract का पालन करता है। Zerocopy lifecycle bits के साथ grouped page-ownership bit security-sensitive होता है, भले ही clearing code सीधे किसी fragment को access न करता हो।<sup>[[1]](#references)[[2]](#references)</sup>

एक robust fix में वे सभी रास्ते शामिल होने चाहिए जिनसे skb बना रह सकता है—जिसमें action continuation और recirculation भी शामिल हैं—और `skb_shinfo()` साझा करने वाले clones का भी ध्यान रखना चाहिए। Consumer side पर, authentication failure, in-place AEAD transform द्वारा पहले ही किए जा चुके plaintext writes को undo नहीं करता। इसलिए decryption शुरू होने से पहले foreign-storage checks किए जाने चाहिए।<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Doyensec netdev fix series: forwarded skb से zerocopy frag markers न हटाएँ](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: Open vSwitch के Forwarded-SKB Marker Stripping से Deterministic ESP Page-Cache LPE संभव](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Doyensec `ovs-pagecache-write` proof of concept](https://github.com/doyensec/ovs-pagecache-write)
- [4] [मूल Fragnesia coalescing path के लिए Linux fix (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Linux ESP consumer-side shared-fragment check (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: IPsec ESP में Galois/Counter Mode (GCM) का उपयोग](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Open vSwitch kernel datapath documentation](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}
