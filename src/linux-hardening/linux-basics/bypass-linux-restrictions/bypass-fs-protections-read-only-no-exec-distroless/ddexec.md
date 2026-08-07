# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Muktadha

Katika Linux, ili kuendesha program, lazima iwepo kama faili na ipatikane kwa namna fulani kupitia mpangilio wa mfumo wa faili (hivi ndivyo `execve()` inavyofanya kazi). Faili hii inaweza kuwa kwenye diski au kwenye RAM (tmpfs, memfd), lakini unahitaji filepath. Hali hii imerahisisha sana kudhibiti kinachoendeshwa kwenye mfumo wa Linux, kugundua threats na zana za attacker, au kuwazuia kabisa kujaribu kuendesha kitu chochote chao (_k.m._ kutowaruhusu users wasio na privileges kuweka executable files mahali popote).

Lakini technique hii imekuja kubadilisha yote hayo. Ikiwa huwezi kuanzisha process unayotaka... **basi hijack process ambayo tayari ipo**.

Technique hii inakuruhusu **kubypass protection techniques za kawaida kama vile read-only, noexec, file-name whitelisting, hash whitelisting...**<sup>[[1]](#references)</sup>

## Dependencies

Script ya mwisho inategemea tools zifuatazo ili kufanya kazi; zinahitaji kupatikana kwenye mfumo unao-attack (kwa default utazipata zote karibu kila mahali):
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

Ikiwa unaweza kurekebisha kiholela memory ya process, basi unaweza kuichukua. Hii inaweza kutumika ku-hijack process iliyopo tayari na kuibadilisha kwa program nyingine. Tunaweza kufanikisha hili kwa kutumia syscall ya `ptrace()` (ambayo inahitaji uwe na uwezo wa kutekeleza syscalls au uwe na gdb kwenye mfumo) au, cha kuvutia zaidi, kwa kuandika kwenye `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

File `/proc/$pid/mem` ni mapping ya moja-kwa-moja ya address space yote ya process (_mf._ kutoka `0x0000000000000000` hadi `0x7ffffffffffff000` katika x86-64). Hii inamaanisha kuwa kusoma kutoka au kuandika kwenye file hii katika offset `x` ni sawa na kusoma au kurekebisha yaliyomo kwenye virtual address `x`.

Sasa, tuna matatizo manne ya msingi ya kukabiliana nayo:

- Kwa ujumla, ni root na owner wa program wa file pekee wanaoweza kuirekebisha.
- ASLR.
- Tukijaribu kusoma au kuandika kwenye address ambayo haija-map katika address space ya program, tutapata I/O error.

Matatizo haya yana solutions ambazo, ingawa si kamilifu, ni nzuri:

- Shell interpreters wengi huruhusu kuunda file descriptors ambazo zitarithiwa na child processes. Tunaweza kuunda fd inayoelekeza kwenye `mem` file ya shell ikiwa na write permissions... hivyo child processes zinazotumia fd hiyo zitaweza kurekebisha memory ya shell.
- ASLR si tatizo hata kidogo; tunaweza kuangalia file ya `maps` ya shell au file nyingine yoyote kutoka procfs ili kupata taarifa kuhusu address space ya process.
- Kwa hiyo tunahitaji kufanya `lseek()` kwenye file. Kutoka kwenye shell hili haliwezi kufanywa isipokuwa tutumie `dd` maarufu.

### Kwa undani zaidi

Hatua hizo ni rahisi kiasi na hazihitaji utaalamu wa aina yoyote kuzielewa:<sup>[[1]](#references)</sup>

- Parse binary tunayotaka ku-run pamoja na loader ili kujua mappings wanazohitaji. Kisha tengeneza "shell"code ambayo, kwa ujumla, itafanya hatua zilezile ambazo kernel hufanya katika kila call ya `execve()`:
- Unda mappings hizo.
- Soma binaries na kuziweka ndani yake.
- Weka permissions.
- Hatimaye initialize stack kwa arguments za program na uweke auxiliary vector (inayohitajika na loader).
- Rukia loader na uiache ifanye yaliyosalia (kupakia libraries zinazohitajika na program).
- Pata kutoka kwenye `syscall` file address ambayo process itarudilia baada ya syscall inayotekeleza.
- Overwrite sehemu hiyo, ambayo itakuwa executable, kwa shellcode yetu (kupitia `mem` tunaweza kurekebisha pages zisizo writable).
- Pitisha program tunayotaka ku-run kwenye stdin ya process (ita-`read()` na "shell"code hiyo).
- Katika hatua hii, ni jukumu la loader kupakia libraries zinazohitajika na program yetu na kurukia ndani yake.

**Angalia tool kwenye** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)<sup>[[1]](#references)</sup>

## EverythingExec

Kuna alternatives kadhaa za `dd`, mojawapo ikiwa `tail`, ambayo kwa sasa ndiyo program chaguomsingi inayotumika kufanya `lseek()` kupitia `mem` file (ambayo ndiyo iliyokuwa sababu pekee ya kutumia `dd`). Alternatives hizo ni:<sup>[[1]](#references)</sup>
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
Ukipata seeker mwingine halali ambaye hajawekwa kwenye script, bado unaweza kuitumia kwa kuweka variable ya `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Zuieni hii, EDRs.

## Marejeleo

- [1] [DDexec: Mbinu ya kuendesha binary bila kuacha faili na kwa kujificha kwenye Linux](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
