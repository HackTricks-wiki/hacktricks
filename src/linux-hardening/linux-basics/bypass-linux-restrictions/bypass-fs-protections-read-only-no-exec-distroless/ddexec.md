# DDexec / EverythingExec

## Muktadha

Katika Linux, ili kuendesha program lazima iwepo kama file, na lazima ipatikane kwa namna fulani kupitia mpangilio wa mfumo wa file (hivi ndivyo `execve()` inavyofanya kazi). File hii inaweza kuwa kwenye disk au kwenye RAM (tmpfs, memfd), lakini unahitaji filepath. Hili limefanya iwe rahisi sana kudhibiti kinachoendeshwa kwenye mfumo wa Linux, kutambua threats na zana za mshambuliaji, au kuwazuia kabisa wasijaribu kuendesha chochote chao (_k.m._ kutowaruhusu users wasio na privileges kuweka executable files popote).

Lakini technique hii inakuja kubadilisha yote haya. Ikiwa huwezi kuanzisha process unayoitaka... **basi unateka moja ambayo tayari ipo**.

Technique hii inakuruhusu **kubypass protection techniques za kawaida kama read-only, noexec, file-name whitelisting, na hash whitelisting**.<sup>[[1]](#references)</sup>

## Dependencies

Script ya mwisho inategemea tools zifuatazo ili kufanya kazi; zinahitaji kupatikana kwenye mfumo unaoushambulia (kwa kawaida utazipata zote karibu kila mahali):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## Mbinu

Ikiwa unaweza kurekebisha kiholela memory ya process, basi unaweza kuichukua. Hii inaweza kutumika hijack process iliyopo tayari na kuibadilisha iwe program nyingine. Tunaweza kutimiza hili kwa kutumia syscall ya `ptrace()` (ambayo inahitaji uwe na uwezo wa kutekeleza syscalls au uwe na gdb kwenye mfumo) au, jambo la kuvutia zaidi, kwa kuandika kwenye `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Faili `/proc/$pid/mem` ni mapping ya moja kwa moja ya address space nzima ya process (_mf._ kutoka `0x0000000000000000` hadi `0x7ffffffffffff000` katika x86-64). Hii inamaanisha kuwa kusoma kutoka au kuandika kwenye faili hii kwenye offset `x` ni sawa na kusoma au kurekebisha maudhui yaliyo kwenye virtual address `x`.

Sasa, tuna matatizo manne ya msingi ya kukabiliana nayo:

- Kwa ujumla, ni root na mmiliki wa program wa faili pekee wanaoweza kuirekebisha.
- ASLR.
- Tukijaribu kusoma au kuandika kwenye address ambayo haija-mapped katika address space ya program, tutapata I/O error.

Matatizo haya yana suluhisho ambazo, ingawa si kamili, ni nzuri:

- Shell interpreters wengi huruhusu kuunda file descriptors ambazo zitarithiwa na child processes. Tunaweza kuunda fd inayoelekeza kwenye faili ya `mem` ya shell ikiwa na ruhusa za kuandika... hivyo child processes zinazotumia fd hiyo zitaweza kurekebisha memory ya shell.
- ASLR si tatizo hata kidogo; tunaweza kuangalia faili ya `maps` ya shell au faili nyingine yoyote kutoka procfs ili kupata taarifa kuhusu address space ya process.
- Kwa hiyo tunahitaji kutumia `lseek()` kwenye faili. Kutoka kwenye shell hili haliwezi kufanywa isipokuwa tutumie `dd` maarufu.

### Kwa maelezo zaidi

Hatua hizi ni rahisi kwa kiasi na hazihitaji utaalamu wa aina yoyote kuzielewa:<sup>[[1]](#references)</sup>

- Parse binary tunayotaka kuendesha pamoja na loader ili kubaini mappings wanazohitaji. Kisha tengeneza "shell"code ambayo, kwa ujumla, itafanya hatua zilezile ambazo kernel hufanya katika kila call ya `execve()`:
- Unda mappings hizo.
- Soma binaries na kuziingiza humo.
- Weka permissions.
- Hatimaye initialize stack ikiwa na arguments za program na uweke auxiliary vector (inayohitajika na loader).
- Jump kwenye loader na uiruhusu ifanye yaliyosalia (kupakia libraries zinazohitajika na program).
- Pata kutoka kwenye faili ya `syscall` address ambayo process itarudi baada ya syscall inayotekeleza.
- Overwrite sehemu hiyo, ambayo itakuwa executable, kwa shellcode yetu (kupitia `mem` tunaweza kurekebisha pages zisizo na ruhusa ya kuandikwa).
- Pitisha program tunayotaka kuendesha kwenye stdin ya process (itasomwa kwa `read()` na "shell"code hiyo).
- Katika hatua hii, ni jukumu la loader kupakia libraries zinazohitajika na program yetu na ku-jump ndani yake.

**Angalia tool katika** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Kuna alternatives kadhaa za `dd`, mojawapo ikiwa `tail`, ambayo kwa sasa ndiyo program default inayotumika kufanya `lseek()` kupitia faili ya `mem` (ambalo ndilo lilikuwa kusudi pekee la kutumia `dd`). Alternatives hizo ni:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
Kwa kuweka variable `SEEKER`, unaweza kubadilisha seeker inayotumika, _kwa mfano_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Ukipata seeker nyingine halali ambayo haijatekelezwa kwenye script, bado unaweza kuitumia kwa kuweka variable ya `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Zuieni hili, EDRs.

## References

- [1] [DDexec: Mbinu ya kuendesha faili za binary bila faili na kwa kujificha kwenye Linux](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
