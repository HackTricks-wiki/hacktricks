# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Muktadha

Linux kwa kawaida huendesha programu kutoka kwenye faili zinazoweza kutekelezwa zilizohifadhiwa kwenye diski au kwenye memory. Inaweza kutambua faili inayoweza kutekelezwa kwa kutumia pathname au file descriptor, kwa hivyo pathname ya kawaida ya filesystem haihitajiki kila wakati.<sup>[[2]](#references)</sup>

DDexec / EverythingExec hutumia memory ya **process ambayo tayari inaendeshwa**. Ukurasa wa [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) unaeleza utekelezaji wa anonymous-file na mbinu zinazohusiana za utambuzi na ukusanyaji wa ushahidi wa forensic; muhtasari wa [Memory Bypasses](index.html#memory-bypasses) pia una viungo vya MemExec na Memdlopen.<sup>[[1]](#references)</sup>

Mbinu hii inakuruhusu **kuzunguka mbinu za kawaida za ulinzi kama vile read-only, noexec, file-name whitelisting na hash whitelisting**.<sup>[[1]](#references)</sup>

## Vitegemezi

Script ya mwisho inategemea zana zifuatazo ili kufanya kazi; zinahitaji kupatikana kwenye mfumo unaoshambulia (kwa kawaida, utazipata kila mahali):

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

Ikiwa unaweza kurekebisha kumbukumbu ya process yoyote upendavyo, basi unaweza kuiteka. Hii inaweza kutumiwa kuteka process iliyopo tayari na kuibadilisha na program nyingine. Tunaweza kufanya hivi kwa kutumia syscall ya `ptrace()` (ambayo inahitaji uwe na uwezo wa kutekeleza syscalls au gdb ipatikane kwenye mfumo) au, jambo la kuvutia zaidi, kwa kuandika kwenye `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Faili ya `/proc/$pid/mem` ni ramani ya moja kwa moja ya nafasi nzima ya anwani ya process (_kwa mfano_, kutoka `0x0000000000000000` hadi `0x7ffffffffffff000` kwenye x86-64). Hii inamaanisha kuwa kusoma kutoka au kuandika kwenye faili hii kwenye offset `x` ni sawa na kusoma au kurekebisha maudhui kwenye anwani pepe `x`.

Sasa, tuna matatizo manne ya msingi ya kukabiliana nayo:

- Kwa jumla, root pekee na mmiliki wa program ya faili hiyo wanaweza kuirekebisha.
- ASLR.
- Tukijaribu kusoma au kuandika kwenye anwani ambayo haijamapishwa kwenye nafasi ya anwani ya program, tutapata hitilafu ya I/O.

Matatizo haya yana suluhisho ambazo, ingawa si kamilifu, zinafaa:

- Interpreters nyingi za shell huruhusu kuunda file descriptors ambazo hurithiwa na child processes. Tunaweza kuunda fd inayoelekeza kwenye faili ya `mem` ya shell kwa ruhusa za kuandika... hivyo child processes zinazotumia fd hiyo zitaweza kurekebisha kumbukumbu ya shell.
- ASLR si tatizo hata kidogo; tunaweza kuangalia faili ya `maps` ya shell au faili nyingine yoyote kutoka procfs ili kupata taarifa kuhusu nafasi ya anwani ya process.
- Kwa hiyo tunahitaji kutumia `lseek()` kwenye faili. Hili haliwezekani kutoka kwenye shell isipokuwa tutumie `dd` maarufu.

### Kwa undani zaidi

Hatua hizi ni rahisi kiasi na hazihitaji utaalamu wowote kuzielewa:<sup>[[1]](#references)</sup>

- Changanua binary tunayotaka kuendesha na loader ili kujua mappings wanazohitaji. Kisha tengeneza "shell"code itakayotekeleza, kwa upana, hatua zilezile ambazo kernel hufanya kila `execve()` inapoitwa:
  - Unda mappings hizo.
  - Soma binaries na kuziweka humo.
  - Weka permissions.
  - Hatimaye, anzisha stack kwa arguments za program na uweke auxiliary vector (inayohitajika na loader).
  - Rukia kwenye loader na uiruhusu iendelee na mambo mengine (kupakia libraries zinazohitajika na program).
- Pata kutoka kwenye faili ya `syscall` anwani ambayo process itarudia baada ya syscall inayotekeleza.
- Andika juu ya eneo hilo, ambalo litaruhusu utekelezaji, kwa kutumia shellcode yetu (kupitia `mem` tunaweza kurekebisha pages zisizoruhusu kuandikwa).
- Pitisha program tunayotaka kuendesha kwenye stdin ya process (itasomwa kwa `read()` na "shell"code hiyo).
- Kwa wakati huu, jukumu la loader ni kupakia libraries zinazohitajika na program yetu na kisha kurukia ndani yake.

**Angalia tool kwenye** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Kuna njia mbadala kadhaa za `dd`; mojawapo, `tail`, ndiyo program inayotumika kwa chaguo-msingi sasa kutumia `lseek()` ndani ya faili ya `mem` (ambayo ndiyo sababu pekee ya kutumia `dd`). Njia hizo mbadala ni:<sup>[[1]](#references)</sup>

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
- [2] [execveat(2) — ukurasa wa mwongozo wa Linux](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}
