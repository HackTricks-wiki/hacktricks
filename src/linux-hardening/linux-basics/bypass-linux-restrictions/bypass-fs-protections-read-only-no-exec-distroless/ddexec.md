# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Muktadha

Katika Linux, ili kuendesha program lazima iwepo kama file, na lazima ipatikane kwa namna fulani kupitia mpangilio wa file system (hivi ndivyo `execve()` inavyofanya kazi). File hii inaweza kuwa kwenye disk au kwenye RAM (tmpfs, memfd), lakini unahitaji filepath. Hili limefanya iwe rahisi sana kudhibiti kinachoendeshwa kwenye mfumo wa Linux, kutambua threats na tools za attacker, au kuwazuia kabisa kujaribu ku-execute kitu chochote chao (_kwa mfano_ kutowaruhusu users wasio na privileges kuweka executable files popote).

Lakini technique hii imekuja kubadilisha yote hayo. Ikiwa huwezi kuanzisha process unayotaka... **basi hijack ile ambayo tayari ipo**.

Technique hii inakuruhusu **kuzunguka protection techniques za kawaida kama read-only, noexec, file-name whitelisting, hash whitelisting...**

## Dependencies

Script ya mwisho inategemea tools zifuatazo ili ifanye kazi; zinahitaji kupatikana kwenye mfumo unao-attack (kwa default utazipata karibu kila mahali):
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
## The technique

Ikiwa unaweza kurekebisha kiholela memory ya process, basi unaweza kuichukua. Hii inaweza kutumika kuteka hijack process iliyopo tayari na kuibadilisha iwe program nyingine. Tunaweza kufanikisha hili kwa kutumia syscall ya `ptrace()` (ambayo inahitaji uwe na uwezo wa kutekeleza syscalls au uwe na gdb kwenye system) au, jambo la kuvutia zaidi, kwa kuandika kwenye `/proc/$pid/mem`.

Faili `/proc/$pid/mem` ni mapping ya moja-kwa-moja ya address space nzima ya process (_k.m._ kutoka `0x0000000000000000` hadi `0x7ffffffffffff000` katika x86-64). Hii inamaanisha kuwa kusoma kutoka au kuandika kwenye faili hii kwenye offset `x` ni sawa na kusoma au kurekebisha yaliyomo kwenye virtual address `x`.

Sasa, tuna matatizo manne ya msingi ya kukabiliana nayo:

- Kwa ujumla, ni root na mwenye faili pekee wanaoweza kuirekebisha.
- ASLR.
- Tukijaribu kusoma au kuandika kwenye address ambayo haijawekwa katika address space ya program, tutapata hitilafu ya I/O.

Matatizo haya yana suluhisho ambazo, ingawa si kamilifu, ni nzuri:

- Shell interpreters nyingi huruhusu kuunda file descriptors ambazo zit inherit na child processes. Tunaweza kuunda fd inayoelekeza kwenye faili ya `mem` ya shell ikiwa na write permissions... hivyo child processes zinazotumia fd hiyo zitaweza kurekebisha memory ya shell.
- ASLR si tatizo hata kidogo; tunaweza kuangalia faili ya `maps` ya shell au faili nyingine yoyote kutoka procfs ili kupata taarifa kuhusu address space ya process.
- Kwa hiyo tunahitaji kufanya `lseek()` juu ya faili. Kutoka kwenye shell hili haliwezi kufanyika isipokuwa tutumie `dd` maarufu.

### In more detail

Hatua ni rahisi kiasi na hazihitaji utaalamu wa aina yoyote kuzielewa:

- Parse binary tunayotaka kuendesha pamoja na loader ili kubaini mappings wanazohitaji. Kisha tengeneza "shell"code ambayo, kwa ujumla, itafanya hatua zilezile ambazo kernel hufanya katika kila mwito wa `execve()`:
- Unda mappings hizo.
- Soma binaries na kuziweka ndani ya mappings hizo.
- Weka permissions.
- Hatimaye initialize stack kwa arguments za program na uweke auxiliary vector (inayohitajika na loader).
- Rukia loader na uiruhusu ifanye yaliyosalia (kupakia libraries zinazohitajika na program).
- Pata kutoka kwenye faili ya `syscall` address ambayo process itarudi baada ya syscall inayotekeleza.
- Overwrite eneo hilo, ambalo litakuwa executable, kwa shellcode yetu (kupitia `mem` tunaweza kurekebisha pages zisizo na write permissions).
- Pitisha program tunayotaka kuendesha kwenye stdin ya process (itasomwa kwa `read()` na "shell"code hiyo).
- Katika hatua hii, ni jukumu la loader kupakia libraries zinazohitajika na program yetu na kisha kuirukia.

**Check out the tool in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Kuna alternatives kadhaa za `dd`, mojawapo ikiwa `tail`, ambayo kwa sasa ndiyo program ya default inayotumika kufanya `lseek()` kupitia faili ya `mem` (ambayo ndiyo ilikuwa sababu pekee ya kutumia `dd`). Alternatives hizo ni:
```bash
tail
hexdump
cmp
xxd
```
Kwa kuweka variable `SEEKER`, unaweza kubadilisha seeker inayotumika, _mfano_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Ukipata seeker nyingine halali ambayo haijatekelezwa kwenye script, bado unaweza kuitumia kwa kuweka variable ya `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Zuieni hii, EDRs.

## Marejeleo

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
