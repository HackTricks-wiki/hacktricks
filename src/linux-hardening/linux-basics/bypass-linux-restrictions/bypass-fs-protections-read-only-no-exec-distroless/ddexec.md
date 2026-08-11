# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Muktadha

Katika Linux, ili kuendesha program lazima iwepo kama faili, na lazima ipatikane kwa namna fulani kupitia mpangilio wa mfumo wa faili (hivi ndivyo `execve()` inavyofanya kazi). Faili hii inaweza kuwa kwenye diski au kwenye ram (tmpfs, memfd), lakini unahitaji filepath. Hili limefanya iwe rahisi sana kudhibiti kinachoendeshwa kwenye mfumo wa Linux, limerahisisha kugundua threats na tools za mshambuliaji au kuwazuia kabisa kujaribu ku-execute chochote chao (_kwa mfano_ kutowaruhusu users wasio na privileges kuweka executable files mahali popote).

Lakini technique hii iko hapa kubadilisha yote hayo. Ikiwa huwezi kuanzisha process unayoitaka... **basi hijack process ambayo tayari ipo**.

Technique hii inakuruhusu **kubypass protection techniques za kawaida kama vile read-only, noexec, file-name whitelisting, na hash whitelisting**.<sup>[[1]](#references)</sup>

## Dependencies

Script ya mwisho inategemea tools zifuatazo ili kufanya kazi; zinahitaji kupatikana kwenye mfumo unaoushambulia (kwa default utazipata zote kila mahali):
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

Ikiwa unaweza kurekebisha kumbukumbu ya process kiholela, basi unaweza kuichukua. Hii inaweza kutumika ku-hijack process iliyopo tayari na kuibadilisha iwe program nyingine. Tunaweza kufanikisha hili kwa kutumia syscall ya `ptrace()` (ambayo inahitaji uwe na uwezo wa kutekeleza syscalls au uwe na gdb kwenye mfumo) au, jambo la kuvutia zaidi, kwa kuandika kwenye `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Faili `/proc/$pid/mem` ni mapping ya one-to-one ya address space nzima ya process (_k. m._ kutoka `0x0000000000000000` hadi `0x7ffffffffffff000` katika x86-64). Hii inamaanisha kuwa kusoma kutoka au kuandika kwenye faili hili katika offset `x` ni sawa na kusoma au kurekebisha yaliyomo kwenye virtual address `x`.

Sasa, tuna matatizo manne ya msingi ya kukabiliana nayo:

- Kwa ujumla, ni root pekee na mwenye programu ya faili anayeweza kuirekebisha.
- ASLR.
- Tukijaribu kusoma au kuandika kwenye address ambayo haija-mapped katika address space ya program, tutapata I/O error.

Matatizo haya yana suluhisho ambazo, ingawa si kamili, ni nzuri:

- Shell interpreters nyingi huruhusu kuunda file descriptors ambazo zitarithiwa na child processes. Tunaweza kuunda fd inayoelekeza kwenye faili ya `mem` ya shell ikiwa na ruhusa za kuandika... hivyo child processes zinazotumia fd hiyo zitaweza kurekebisha kumbukumbu ya shell.
- ASLR si tatizo hata kidogo; tunaweza kuangalia faili la `maps` la shell au faili lingine lolote kutoka procfs ili kupata taarifa kuhusu address space ya process.
- Kwa hiyo tunahitaji kufanya `lseek()` kwenye faili. Kutoka kwenye shell hili haliwezi kufanywa isipokuwa kwa kutumia `dd` maarufu.

### Kwa maelezo zaidi

Hatua hizi ni rahisi kiasi na hazihitaji utaalamu wa aina yoyote kuzielewa:<sup>[[1]](#references)</sup>

- Parse binary tunayotaka ku-run pamoja na loader ili kujua ni mappings zipi zinahitajika. Kisha tengeneza "shell"code ambayo, kwa ujumla, itafanya hatua zilezile ambazo kernel hufanya kila inapoitwa `execve()`:
- Unda mappings hizo.
- Soma binaries ndani yake.
- Weka permissions.
- Hatimaye, initialize stack kwa arguments za program na uweke auxiliary vector (inayohitajika na loader).
- Rukia loader na uiruhusu ifanye yaliyosalia (kupakia libraries zinazohitajika na program).
- Pata kutoka kwenye faili la `syscall` address ambayo process itarudia baada ya syscall inayotekeleza.
- Overwrite sehemu hiyo, ambayo itakuwa executable, kwa shellcode yetu (kupitia `mem` tunaweza kurekebisha pages zisizoandikika).
- Pitisha program tunayotaka ku-run kwenye stdin ya process (ita-`read()` na "shell"code hiyo).
- Katika hatua hii, loader ndiye anayepaswa kupakia libraries zinazohitajika na program yetu na kurukia ndani yake.

**Angalia tool katika** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Kuna alternatives kadhaa za `dd`, mojawapo ikiwa `tail`, ambayo kwa sasa ndiyo program chaguo-msingi inayotumika kufanya `lseek()` kupitia faili la `mem` (ambayo ndiyo ilikuwa sababu pekee ya kutumia `dd`). Alternatives hizo ni:<sup>[[1]](#references)</sup>
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

- [1] [DDexec: Mbinu ya kuendesha binary bila faili na kwa usiri kwenye Linux](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
