# Kuondoa alama ya skb iliyosambazwa mbele na Open vSwitch kwa ajili ya kuandika kwenye page cache kupitia ESP

{{#include ../../../banners/hacktricks-training.md}}

Mbinu muhimu ya kutumia udhaifu kwenye Linux kernel ni **kuondoa metadata ya umiliki kutoka kwa skb bila kuondoa fragment zake za kigeni**, kisha kuelekeza skb hiyo kwa consumer anayeandika moja kwa moja kwenye eneo lilipo. Katika hali ya Open vSwitch (OVS), upcall ya userspace inaposhindwa, huondoa `SKBFL_SHARED_FRAG` kutoka kwa skb ya `MSG_ZEROCOPY` ambayo bado ipo hai; baadaye ESP husimbua moja kwa moja juu ya folio ya page cache ya faili ya kusoma tu. Hii hutoa uandishi wa page cache wa ndani unaoweza kutabirika, na imefuatiliwa kupitia CVE-2026-90049, CVE-2026-89487, na CVE-2026-80977.<sup>[[1]](#references)[[2]](#references)</sup>

Hili ni suala la aina ya Copy Fail/Dirty Frag badala ya ufisadi wa kawaida wa kumbukumbu: halihitaji race wala ufichuaji wa anwani, faili inahitaji tu kusomeka, na baiti zilizobadilishwa huwa kwenye page cache badala ya diski.<sup>[[2]](#references)[[3]](#references)</sup>

## Kanuni ya usalama: fragment za kigeni lazima ziendelee kuwa na alama

`SKBFL_SHARED_FRAG` huwajulisha consumers wanaoandika moja kwa moja kwamba fragment ya skb inaweza kurejelea hifadhi ambayo hawamiliki kwa faragha. Fast path ya ESP katika `esp_input()` inaweza kusimbua skb isiyo ya kawaida na ambayo haijaclonewa moja kwa moja tu ikiwa `skb_has_shared_frag()` ni false; vinginevyo, `skb_cow_data()` hutengeneza hifadhi ya faragha kwanza. Ukaguzi huu wa upande wa consumer uliongezwa baada ya Dirty Frag.<sup>[[5]](#references)</sup>

Kwa hiyo, kanuni hii ina sehemu mbili huru:<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. Waandishi wanaoandika moja kwa moja lazima wakague `SKBFL_SHARED_FRAG` na kunakili data iliyoshirikiwa kabla ya kuibadilisha.
2. Kila njia ya clone, coalesce, transfer, au forwarding lazima ihifadhi alama hiyo mradi tu ukurasa wa kigeni bado umeambatishwa.

Fragnesia ilikiuka kanuni ya pili ilipohamisha fragment descriptors katika `skb_try_coalesce()`. Njia ya OVS ni tofauti kwa namna fiche: haihamishi fragment hata kidogo; huondoa alama **moja kwa moja kwenye skb asilia kisha huendelea kuisambaza mbele**.<sup>[[2]](#references)[[4]](#references)</sup>

## Uwezekano wa kufikia OVS bila upendeleo

Kernel datapath ya OVS hudhibitiwa kupitia familia za generic-netlink kama `ovs_datapath`, `ovs_vport`, `ovs_flow`, na `ovs_packet`. Operesheni zake zinazobadilisha hali hutumia `GENL_UNS_ADMIN_PERM` inayozingatia namespace, kwa hiyo mchakato unaoendeshwa chini ya `unshare -Urn` hupata `CAP_NET_ADMIN` inayohitajika kuunda datapath, kuunganisha veth, na kusakinisha flow actions ndani ya network namespace yake yenyewe. Kutatua familia ya OVS kunaweza pia kupakia kiotomatiki `openvswitch.ko`; `CAP_SYS_MODULE` ya host, `ovs-vsctl`, na `ovs-vswitchd` hazihitajiki kwa sehemu hii ya attack surface.<sup>[[2]](#references)[[7]](#references)</sup>

Tofauti muhimu ni kati ya aina mbili za upcall:<sup>[[2]](#references)[[7]](#references)</sup>

- **Flow miss** hutuma packet kwa `ovs-vswitchd`; upcall ikishindwa, packet kwa kawaida hutupwa.
- Kitendo cha wazi cha `OVS_ACTION_ATTR_USERSPACE` hutuma nakala iliyokopwa kwa port ID iliyochaguliwa, kisha hutekeleza actions zinazofuata kwenye skb asilia.

Kwa hiyo, mshambuliaji anaweza kusakinisha flow yenye muundo kama huu:<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

Hakuna listener inayomiliki port ID iliyochaguliwa, hivyo hatua ya userspace hushindwa kwa namna inayotabirika, huku hatua ya `OUTPUT` inayofuata ikiweka packet ya awali hai.<sup>[[1]](#references)[[2]](#references)</sup>

## Chanzo cha tatizo: `skb_tx_error()` kwenye packet ambayo bado iko hai

Njia ya hitilafu ya OVS upcall iliyo hatarini hutumia `skb_tx_error(skb)`. Helper hiyo iliundwa kwa ajili ya hitilafu ya transmit ambapo skb hufutwa baadaye; hukamilisha uhasibu wa zerocopy kupitia `skb_zcopy_clear()`, ambayo mask ya flags yake kihistoria pia iliondoa `SKBFL_SHARED_FRAG`. OVS ilipuuza hitilafu ya userspace-action na kuendelea na orodha yake ya actions, hivyo kukiuka mkataba wa muda wa maisha wa helper.<sup>[[1]](#references)[[2]](#references)</sup>

Mabadiliko ya hali yanayoweza kutumiwa vibaya ni:<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

Hili hufanya kazi tu wakati `skb_zcopy()` inapata hali ya zerocopy. Kipande kilicho na `SKBFL_SHARED_FRAG` pekee hakitoshi; `MSG_ZEROCOPY` ni muhimu kwa sababu huunda `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG` na pia huweka `SKBFL_DONT_ORPHAN`. Hii ya mwisho husababisha `skb_orphan_frags()` kuruka kubadilisha kurasa za nje wakati wa nakala ya OVS kwenda userspace.<sup>[[2]](#references)[[3]](#references)</sup>

## Kuunda primitive ya uandishi

Mchakato wa trigger kutoka mwanzo hadi mwisho una vipengele vifuatavyo.<sup>[[2]](#references)[[3]](#references)</sup>

1. Ingia kwenye user namespace na network namespace za faragha kwa kutumia `unshare -Urn`.
2. Ramani faili lengwa inayosomeka kwa kutumia `PROT_READ | MAP_SHARED`.
3. Tumia netns tofauti ya mtumaji na jozi ya veth; loopback ya ndani ingenakili kurasa zilizokopwa na kuharibu primitive.
4. Jenga OVS datapath na flow ya `USERSPACE` kisha `OUTPUT` inayosababisha hitilafu.
5. Sakinisha hali ya XFRM ya ESP-in-UDP katika transport mode kwa kutumia `rfc4106(gcm(aes))` na porti ya UDP 4500.
6. Tuma datagramu moja ya `MSG_ZEROCOPY` yenye iovec iliyopangwa kama `[ESP header | mapped file bytes | invalid ICV]`.

Hali ya XFRM hutumia baiti 20 za nyenzo muhimu za AES-128-GCM: baiti 16 za ufunguo wa AES zikifuatiwa na salt ya RFC 4106 yenye baiti nne. Kwa IV dhahiri ya baiti nane iliyochaguliwa, usiri wa payload huanza na kizuizi cha kaunta `salt || IV || be32(2)`; thamani ya kaunta 1 huficha matokeo ya uthibitishaji badala yake.<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

Mara OVS inapoondoa marker, ESP hutumia njia yake ya no-copy na kutekeleza `plaintext = ciphertext XOR keystream` kwenye fragment inayotokana na faili. Uthibitishaji hukaguliwa **baada** ya mabadiliko haya, kwa hivyo ICV batili iliyojaa sufuri husababisha packet ishindwe kwa `-EBADMSG` baada tu ya byte za page-cache kuwa tayari zimebadilika.<sup>[[2]](#references)</sup>

### Kubadilisha GCM iwe byte zilizochaguliwa

Kwa byte ya sasa `C` na byte inayotakiwa `P`, byte ya kwanza ya keystream ya payload lazima iwe `C XOR P`. Key ya AES na salt zikiwa zimewekwa, pitia suffix ya biti 16 ya IV iliyo wazi na uandae mapema suffix moja kwa kila byte ya kwanza ya keystream inayowezekana:<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

Utekelezaji wa umma unaweka kikomo cha ciphertext kuwa baiti 32 na husogeza fragment ya faili kwa baiti moja kwa kila packet. Baiti ya kwanza iliyochaguliwa hubadilisha baiti ya kwanza ya ziada ya packet iliyotangulia; `pread()` husasisha `C` kabla ya kila packet, baiti zinazofanana hurukwa, na packet ya mwisho hufupishwa ili maandishi yasivuke masafa yaliyoombwa. Kwa hivyo, jedwali la utafutaji lenye maingizo 256 hugeuza primitive hii kuwa write ya page cache yenye maudhui yaliyochaguliwa kwa kila baiti, kwa takriban packet moja kwa kila baiti tofauti.<sup>[[2]](#references)[[3]](#references)</sup>

## Kuandika kwenye page cache ili kupata root

Lengo linalofaa ni executable iliyopo ya setuid-root. PoC hubadilisha baiti 160 za kwanza kwa ELF tuli kamili iliyo na `PT_LOAD` moja ya read/execute yenye anwani isiyobadilika, isiyo na `PT_INTERP`, na code inayopiga `setuid(0)` kabla ya `execve("/bin/sh", ...)`. Hii huepusha kutegemea entry point ya binary ya awali, mpangilio wa PIE, dynamic loader au relocations.<sup>[[2]](#references)[[3]](#references)</sup>

Mabadiliko hayo yanaonekana katika user namespaces zote kwa sababu page cache haijawekwa kwenye namespace. Folio iliyobadilishwa haijawekewa alama ya kuwa dirty, kwa hivyo haiandikwi kurudi kwenye diski; tekeleza lengo likiwa bado kwenye kumbukumbu, kisha ondoa uharibifu wa muda kwa `posix_fadvise(..., POSIX_FADV_DONTNEED)` ili usomaji unaofuata upakie upya maudhui ya awali kutoka kwenye diski.<sup>[[2]](#references)[[3]](#references)</sup>

## Ukaguzi wa uwezekano wa kuathirika na upunguzaji wa hatari

Kwanza kagua kernel halisi ya vendor. Vigezo muhimu vya uwezekano wa kuathirika ni user namespaces zisizohitaji ruhusa za juu, upatikanaji au uwepo wa OVS, na upatikanaji wa utekelezaji wa ESP.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

Sasisha kernel iwe na mfululizo kamili wa marekebisho; marekebisho ya mwisho yanashughulikia njia ya recirculation na kuepuka kubadilisha hali ya `skb_shinfo()` inayoshirikiwa, huku pia yakifunga njia inayohusiana ya strip katika `skb_zerocopy()`.<sup>[[1]](#references)[[2]](#references)</sup>

Ikiwa OVS haitumiki, zuia upakiaji kupitia alias na kwa jina kwa kutumia sheria ya `install` ya modprobe, badala ya kutegemea `blacklist` pekee. Ikiwa host haikomeshi IPsec na ESP ni modular, udhibiti huohuo unaweza kuondoa decrypt sink.<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

Sheria hizi hazisaidii wakati module tayari imepakiwa au kipengele kimejengwa ndani ya kernel. Kuzima user namespaces zisizohitaji ruhusa pia huondoa chanzo cha uwezo wa namespace, lakini kunaweza kuvuruga browsers, Flatpak, Podman na workloads nyingine za sandboxing/container.<sup>[[2]](#references)</sup>

## Mafunzo ya ukaguzi

Unapokagua zero-copy networking, usiweke utafutaji kwenye helpers zinazokopi au kuhamisha fragments pekee. Pia tambua error/completion helpers zinazofuta flags zilizowekwa pamoja, kisha uthibitishe kuwa kila caller inafuata mkataba uliowekwa wa muda wa uhai wa skb. Bit ya umiliki wa ukurasa iliyowekwa pamoja na bits za mzunguko wa maisha wa zerocopy ni nyeti kwa usalama, hata kama msimbo wa kufuta flags haufikii fragment moja kwa moja.<sup>[[1]](#references)[[2]](#references)</sup>

Marekebisho thabiti lazima yashughulikie njia zote ambazo skb inaweza kuendelea kuwepo—ikiwemo action continuation na recirculation—na yazingatie clones zinazoshiriki `skb_shinfo()`. Kwa upande wa consumer, kushindwa kwa uthibitishaji hakubatilishi uandishi wa plaintext ambao transform ya AEAD inayofanya kazi in-place tayari imefanya; kwa hiyo, ukaguzi wa foreign storage lazima ufanyike kabla ya decryption kuanza.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Mfululizo wa marekebisho ya Doyensec netdev: net: usiondoe alama za zerocopy frag kutoka kwa skb iliyotumwa mbele](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: Kuondolewa kwa Alama za Forwarded-SKB katika Open vSwitch Kunamwezesha LPE ya ESP Page-Cache Inayoweza Kurudiwa kwa Uhakika](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Proof of concept ya Doyensec `ovs-pagecache-write`](https://github.com/doyensec/ovs-pagecache-write)
- [4] [Marekebisho ya Linux kwa njia asilia ya kuunganisha ya Fragnesia (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Ukaguzi wa Linux wa fragments zilizoshirikiwa upande wa consumer wa ESP (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: Matumizi ya Galois/Counter Mode (GCM) katika IPsec ESP](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Nyaraka za kernel datapath ya Open vSwitch](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}
