# लक्षित instrumentation के लिए WinDbg automation

{{#include ../../banners/hacktricks-training.md}}

WinDbg और WinDbgX startup पर, exceptions के दौरान और breakpoints hit होने पर debugger commands चला सकते हैं। इससे fuzzing या reversing session में हर event पर manually रुकने के बजाय, केवल input-driven path के आसपास state collect की जा सकती है।<sup>[[1]](#references)</sup>

## उपयोगी exception पर शुरू करें

`-c` शुरुआती debugger break पर commands चलाता है। Setup के बाद resume करने के लिए `;g` जोड़ें। Unattended WinDbg Classic run में, `-logo` command window को log में लिखता है, `-Q` automatic workspace saving बंद करता है, और `-G` अंतिम breakpoint को अनदेखा करता है, ताकि target के exit होते ही session समाप्त हो जाए। WinDbgX भी `-c` स्वीकार करता है; इसके बाद configured Startup commands चलती हैं।<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

Access violations के लिए, **`sxe av` first chance पर break करता है**, **`sxd av` first chance को छोड़ता है, लेकिन unhandled second chance पर break करता है**, और **`sxi av` दोनों chances को अनदेखा करता है**। यहाँ लेख में `sxi`/`sxd` के विवरण उलटे हैं: Microsoft `sxd` को second-chance filter और `sxi` को ignore के रूप में दस्तावेज़ित करता है। First-chance command के लिए `-c` और second-chance command के लिए `-c2` का उपयोग करें; केवल filter `sxd` होने से first-chance `-c` handler second-chance handler नहीं बन जाता। सक्रिय filters की पुष्टि `sx` से करें।<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

पहली command केवल unhandled access violation होने पर registers, stack trace और exception analysis एकत्र करती है। दूसरी command module load होने पर `lm` चलाती है। Breakpoint (`bp`), module-load (`ld`) और access-violation (`av`) events के lifecycles अलग-अलग होते हैं, इसलिए debugger breakpoints पर निर्भर रहते समय `bp` को globally ignore न करें।<sup>[[1]](#references)[[2]](#references)</sup>

## नियंत्रित trigger से महँगे breakpoints को सक्रिय करें

ऐसा script-visible या अन्यथा input-controlled function चुनें, जिसे रुचि वाले path से ठीक पहले call किया जा सके। जाँच के लिए allocator, parser या API calls पर **action breakpoints** लगाएँ। उन्हें ID के ज़रिए `bd` से disable करें। एक **trigger breakpoint** लगाएँ, जिसके साथ जुड़ी command उन IDs को `be` से enable करे, फिर `g` से execution resume करे; दूसरा नियंत्रित trigger उन्हें फिर disable कर सकता है। Trigger जोड़ने से पहले `bl` से IDs जाँच लें, क्योंकि वे breakpoints बनाने के क्रम पर निर्भर करती हैं। इससे हल्के control points को महँगी tracing से अलग रखा जा सकता है और target की timing तथा heap layout में बदलाव सीमित रहते हैं।<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

दोनों symbols resolve करने के बाद, command pattern नीचे दिया गया है। Bracket में दिए symbols और `bl` से मिले action breakpoint ID को बदलें; यह न मानें कि ID शून्य है।<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Action breakpoint commands `@$ip` और `%y` (symbolized address) प्रिंट कर सकते हैं, चुने हुए arguments या memory dump कर सकते हैं, और फिर execution जारी रख सकते हैं। अगर conditional breakpoint केवल चुनी हुई range के pointers को log करता है, तो पहले पुष्टि करें कि range में test input शामिल है; गलत condition चुपचाप evidence खो देती है।<sup>[[1]](#references)</sup>

### Symbols के साथ trigger खोजें

अगर implementation module अज्ञात है, तो सभी loaded modules में खोजें। `bm` हर matching symbol पर breakpoints सेट करता है; script-visible function को invoke करें और देखें कि कौन-सा breakpoint fire होता है। उदाहरण के लिए, source debug किए जा रहे renderer में `Math.cos(0)` चलाता है—किसी भी browser process में नहीं।<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

एक बार किसी hit से सटीक function की पहचान हो जाए, तो उसकी containing image का पता लगाने के लिए `lm a <symbol>` और module-relative offset की गणना करने के लिए `? <symbol> - <module>` का उपयोग करें। WinDbg किसी executable और DLL के लिए एक ही छोटा module name दिखा सकता है, इसलिए किसी दूसरे process में offset का उपयोग करने से पहले image path की पुष्टि करें। अतिरिक्त overhead से बचने के लिए wildcard breakpoints को सत्यापित symbol तक सीमित करें।<sup>[[1]](#references)</sup>

### बिना symbols के candidate खोजें

Corelan का Frida-आधारित `corelan_trigscan.py` चुने गए process module को floating-point, SSE, AVX और trigonometric instruction patterns के लिए scan करता है। यह `corelan_trigscan.bps` और छोटी क्रमांकित `.bps` files में WinDbg breakpoint commands बनाता है। इसे Python और `frida-tools` के साथ target पर **किसी दूसरे debugger को attach किए बिना** चलाएँ; इसके बाद उसी process/module में WinDbg attach करें और breakpoint का प्रबंधनीय batch load करें।<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

किसी ज्ञात module-relative offset के लिए, सभी emitted breakpoints import करने से पहले पुष्टि करें कि वह thresholds पार करता है:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` relevant-instruction density है, `--min-relevant` और `--min-total` instruction-count floors सेट करते हैं, और `--min-trig` के लिए मजबूत trig-जैसे signals ज़रूरी हैं। अगर कोई ज्ञात function छूट जाए, तो उसके **module-relative** offset को `--check-offset` में दें, ताकि उसके prologue, density, counts और indirect calls की जाँच की जा सके। किसी thin wrapper की density कम हो सकती है और उसमें कोई trig instruction नहीं हो सकता। Thresholds कम करें और wrappers खोजते समय script का वास्तविक `--min-icall 1` option इस्तेमाल करें (`--min-ical` नहीं); direct callees का analysis होता है, लेकिन indirect targets को विश्वसनीय ढंग से follow नहीं किया जा सकता। जब कई generated breakpoints से WinDbg धीमा हो, तो छोटे `--splitsize` batches मदद करते हैं। किसी candidate को तब तक validated नहीं माना जाता, जब तक intended input से उसका breakpoint fire न हो जाए।<sup>[[1]](#references)[[6]](#references)</sup>

## Small debugger programs and PyKD

जब कोई condition विश्वसनीय हो, तो `.if` इस्तेमाल करें; whitespace-delimited output पर iterate करने के लिए `.foreach` इस्तेमाल करें; और memory या structures को traverse करने के लिए pseudo-registers के साथ `.for` इस्तेमाल करें। `.foreach` columns को **preserve नहीं करता**: उदाहरण के लिए, variable-width `lm` output एक खराब input है, जबकि `lm 1m` हर token में एक module name देता है। अगर अनुमानित condition failing path को छिपा सकती हो, तो पहले unfiltered data log करें।<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

`as name value` से बनाए गए Aliases typed variables नहीं, बल्कि textual substitutions होते हैं। `al` इन्हें सूचीबद्ध करता है, `ad name` किसी alias को हटाता है, और `${name}` स्पष्ट रूप से उसका expansion करता है। `bp`, `x` या `r` जैसे नामों से बचें, क्योंकि alias किसी built-in command को shadow कर सकता है। Pointer arithmetic, जैसे `poi(@$t0)`, के लिए MASM expressions उपयुक्त हैं; symbols मौजूद होने पर `@@c++(...)` hard-coded structure offsets से बचते हुए typed fields को access कर सकता है।<sup>[[1]](#references)</sup>

लंबे command sequences को command file में रखें। `$$><filename` पंक्तियों को एक command block में जोड़ता है और इसके बाद semicolon से अलग किया गया debugger command चलाने देता है। Multiline control structures फिर भी नाज़ुक हो सकते हैं; हर `.if` या `.for` statement को एक ही पंक्ति में रखें। Startup पर `-c` से वही file invoke की जा सकती है।<sup>[[1]](#references)[[8]](#references)</sup>

ऐसे logic के लिए जिसे command language में लिखना कठिन हो, PyKD Python के ज़रिए typed structures, registers, memory और debugger output तक पहुँच देता है। उदाहरण के लिए, `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` PEB fields को access करता है, `pykd.loadBytes(address, size)` memory पढ़ता है, और `pykd.dbgCommand("lm")` parsing के लिए debugger output लौटाता है। संभवतः unterminated data के लिए unbounded string reads की जगह bounded `loadChars`/`loadWChars` को प्राथमिकता दें। PyKD का `disasm(address).asm(instruction)` उस address पर assembled bytes **लिखता है**, इसलिए live process में opcodes प्राप्त करने के लिए इसका उपयोग करते समय मूल memory को सुरक्षित रखें और फिर restore करें।<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: Debugging - WinDBG(X) Automation और Scripting - भाग 1](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx, sxd, sxe, sxi, sxn, sxr, sx- (Exceptions सेट करना)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be (Breakpoint सक्षम करना)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd (Breakpoint अक्षम करना)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp, bu, bm (Breakpoint सेट करना)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Corelan trigscan source](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: WinDbg Command-Line Options](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: Script File चलाना](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
