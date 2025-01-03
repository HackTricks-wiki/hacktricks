# DDexec / EverythingExec

{{#include ../../../banners/hacktricks-training.md}}

## Muktadha

Katika Linux ili kuendesha programu lazima iwepo kama faili, lazima iweze kupatikana kwa njia fulani kupitia hierarchi ya mfumo wa faili (hii ndiyo jinsi `execve()` inavyofanya kazi). Faili hii inaweza kuwa kwenye diski au kwenye ram (tmpfs, memfd) lakini unahitaji njia ya faili. Hii imefanya iwe rahisi kudhibiti kile kinachokimbia kwenye mfumo wa Linux, inafanya iwe rahisi kugundua vitisho na zana za mshambuliaji au kuzuia wao kujaribu kutekeleza chochote chao kabisa (_e. g._ kutoruhusu watumiaji wasio na mamlaka kuweka faili zinazoweza kutekelezwa mahali popote).

Lakini mbinu hii iko hapa kubadilisha yote haya. Ikiwa huwezi kuanzisha mchakato unayotaka... **basi unachukua moja iliyopo tayari**.

Mbinu hii inakuwezesha **kuzidi mbinu za kawaida za ulinzi kama vile kusoma tu, noexec, orodha ya majina ya faili yaliyoruhusiwa, orodha ya hash iliyoruhusiwa...**

## Mahitaji

Script ya mwisho inategemea zana zifuatazo ili kufanya kazi, zinahitaji kupatikana katika mfumo unaoshambulia (kwa default utaona zote kila mahali):
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

Ikiwa unaweza kubadilisha kwa njia isiyo na mipaka kumbukumbu ya mchakato, basi unaweza kuichukua. Hii inaweza kutumika kuhamasisha mchakato uliopo tayari na kuubadilisha na programu nyingine. Tunaweza kufikia hili ama kwa kutumia syscall ya `ptrace()` (ambayo inahitaji uwe na uwezo wa kutekeleza syscalls au kuwa na gdb inapatikana kwenye mfumo) au, kwa njia ya kuvutia zaidi, kuandika kwenye `/proc/$pid/mem`.

Faili ya `/proc/$pid/mem` ni ramani ya moja kwa moja ya nafasi yote ya anwani ya mchakato (_e. g._ kutoka `0x0000000000000000` hadi `0x7ffffffffffff000` katika x86-64). Hii ina maana kwamba kusoma au kuandika kwenye faili hili kwa offset `x` ni sawa na kusoma au kubadilisha yaliyomo kwenye anwani ya virtual `x`.

Sasa, tuna matatizo manne ya msingi ya kukabiliana nayo:

- Kwa ujumla, ni root tu na mmiliki wa programu ya faili wanaweza kuibadilisha.
- ASLR.
- Ikiwa tutajaribu kusoma au kuandika kwenye anwani isiyopangwa katika nafasi ya anwani ya programu, tutapata kosa la I/O.

Matatizo haya yana suluhisho ambayo, ingawa si kamilifu, ni mazuri:

- Watafsiri wengi wa shell huruhusu uundaji wa vigezo vya faili ambavyo vitarithiwa na michakato ya watoto. Tunaweza kuunda fd inayotaja faili ya `mem` ya shell yenye ruhusa za kuandika... hivyo michakato ya watoto inayotumia fd hiyo itakuwa na uwezo wa kubadilisha kumbukumbu ya shell.
- ASLR si tatizo, tunaweza kuangalia faili ya `maps` ya shell au nyingine yoyote kutoka procfs ili kupata taarifa kuhusu nafasi ya anwani ya mchakato.
- Hivyo tunahitaji `lseek()` juu ya faili. Kutoka kwa shell hili haliwezi kufanywa isipokuwa kwa kutumia `dd` maarufu.

### Kwa maelezo zaidi

Hatua ni rahisi na hazihitaji aina yoyote ya utaalamu ili kuzielewa:

- Parse binary tunayotaka kuendesha na loader ili kugundua ni ramani gani wanahitaji. Kisha tengeneza "shell"code itakayofanya, kwa ujumla, hatua sawa na zile ambazo kernel inafanya kila wakati inapoita `execve()`:
- Unda ramani hizo.
- Soma binaries ndani yao.
- Weka ruhusa.
- Hatimaye anza stack na hoja za programu na weka vector ya ziada (inayohitajika na loader).
- Ruka kwenye loader na acha ifanye mengine (pakia maktaba zinazohitajika na programu).
- Pata kutoka kwa faili ya `syscall` anwani ambayo mchakato utarudi baada ya syscall inayotekelezwa.
- Badilisha mahali hapo, ambalo litakuwa la kutekelezeka, na shellcode yetu (kupitia `mem` tunaweza kubadilisha kurasa zisizoweza kuandikwa).
- Pass programu tunayotaka kuendesha kwa stdin ya mchakato (itakuwa `read()` na "shell"code hiyo).
- Katika hatua hii ni juu ya loader kupakia maktaba zinazohitajika kwa programu yetu na kuruka ndani yake.

**Angalia chombo katika** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Kuna chaguzi kadhaa za `dd`, moja ya hizo, `tail`, kwa sasa ndiyo programu ya default inayotumika ku `lseek()` kupitia faili ya `mem` (ambayo ilikuwa sababu pekee ya kutumia `dd`). Chaguzi hizo ni:
```bash
tail
hexdump
cmp
xxd
```
Kuweka variable `SEEKER` unaweza kubadilisha mtafutaji anayetumika, _e. g._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Ikiwa utapata mtafutaji mwingine halali ambao haujatekelezwa katika skripti, bado unaweza kuutumia kwa kuweka kiambishi cha `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Block hii, EDRs.

## Marejeleo

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../banners/hacktricks-training.md}}
