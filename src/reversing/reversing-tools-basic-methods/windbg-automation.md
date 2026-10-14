# WinDbg automation for targeted instrumentation

{{#include ../../banners/hacktricks-training.md}}

WinDbg and WinDbgX can run debugger commands at startup, on exceptions, and when breakpoints fire. This lets a fuzzing or reversing session collect state only around an input-driven path instead of stopping manually at every event.<sup>[[1]](#references)</sup>

## Start at a useful exception

`-c` runs commands at the initial debugger break. Append `;g` to resume after setup. For an unattended WinDbg Classic run, `-logo` writes the command window to a log, `-Q` disables automatic workspace saving, and `-G` ignores the final breakpoint so the session ends when the target exits. WinDbgX also accepts `-c`; its configured Startup commands run afterward.<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

For access violations, **`sxe av` breaks on first chance**, **`sxd av` skips first chance but breaks on unhandled second chance**, and **`sxi av` ignores both chances**. The article's `sxi`/`sxd` descriptions are reversed here: Microsoft documents `sxd` as the second-chance filter and `sxi` as ignore. Use `-c` for a first-chance command and `-c2` for a second-chance command; a first-chance `-c` handler does not become a second-chance handler merely because the filter is `sxd`. Confirm active filters with `sx`.<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

The first command collects registers, a stack trace, and exception analysis only for an unhandled access violation. The second runs `lm` when a module loads. Breakpoint (`bp`), module-load (`ld`), and access-violation (`av`) events have different lifecycles, so do not globally ignore `bp` when relying on debugger breakpoints.<sup>[[1]](#references)[[2]](#references)</sup>

## Gate expensive breakpoints with a controlled trigger

Choose a script-visible or otherwise input-controlled function that can be called immediately before the path of interest. Install **action breakpoints** on the allocator, parser, or API calls to inspect. Disable them by ID with `bd`. Install a **trigger breakpoint** whose attached command enables those IDs with `be`, then resumes with `g`; a second controlled trigger can disable them again. Check IDs with `bl` before wiring the trigger, because they depend on breakpoint creation order. This separates cheap control points from expensive tracing and limits changes to the target's timing and heap layout.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

After resolving the two symbols, the command pattern is below. Replace the bracketed symbols and the action breakpoint ID returned by `bl`; do not assume it is zero.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Action breakpoint commands can print `@$ip` and `%y` (symbolized address), dump selected arguments or memory, and then continue. If a conditional breakpoint logs only pointers in a selected range, first verify that the range actually covers the test input; a wrong condition silently loses evidence.<sup>[[1]](#references)</sup>

### Find a trigger with symbols

Search all loaded modules if the implementation module is unknown. `bm` sets breakpoints on every matching symbol; invoke the script-visible function and inspect which breakpoint fires. For example, the source drives `Math.cos(0)` in the renderer being debugged, not just any browser process.<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

Once a hit identifies the exact function, use `lm a <symbol>` to resolve its containing image and `? <symbol> - <module>` to calculate a module-relative offset. WinDbg can display the same short module name for an executable and a DLL, so verify the image path before using the offset in another process. Narrow the wildcard breakpoints to the verified symbol to avoid overhead.<sup>[[1]](#references)</sup>

### Find a candidate without symbols

Corelan's Frida-based `corelan_trigscan.py` scans a selected process module for floating-point, SSE, AVX, and trigonometric instruction patterns. It emits WinDbg breakpoint commands in `corelan_trigscan.bps` and smaller numbered `.bps` files. Run it with Python and `frida-tools` against the target **without another debugger attached**; attach WinDbg to the same process/module afterward and load a manageable breakpoint batch.<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

For a known module-relative offset, validate that it survives the thresholds before importing all emitted breakpoints:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` is relevant-instruction density, `--min-relevant` and `--min-total` set instruction-count floors, and `--min-trig` requires strong trig-like signals. If a known function is missed, pass its **module-relative** offset to `--check-offset` to inspect its prologue, density, counts, and indirect calls. A thin wrapper may have low density and no trig instruction. Lower the thresholds and, if searching for wrappers, use the script's actual `--min-icall 1` option (not `--min-ical`); direct callees are analyzed, but indirect targets cannot reliably be followed. Smaller `--splitsize` batches help when many generated breakpoints slow WinDbg. A candidate is not validated until the intended input makes its breakpoint fire.<sup>[[1]](#references)[[6]](#references)</sup>

## Small debugger programs and PyKD

Use `.if` when a condition is reliable, `.foreach` to iterate whitespace-delimited output, and `.for` with pseudo-registers to walk memory or structures. `.foreach` does **not** preserve columns: variable-width `lm` output, for example, is a poor input, while `lm 1m` yields one module name per token. Log unfiltered data first if a guessed condition could hide the failing path.<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

Aliases created with `as name value` are textual substitutions, not typed variables. `al` lists them, `ad name` deletes one, and `${name}` forces an unambiguous expansion. Avoid names such as `bp`, `x`, or `r` because an alias can shadow a built-in command. MASM expressions suit pointer arithmetic such as `poi(@$t0)`; `@@c++(...)` can access typed fields when symbols are present, avoiding hard-coded structure offsets.<sup>[[1]](#references)</sup>

Put longer command sequences in a command file. `$$><filename` joins lines into a single command block and permits a following semicolon-delimited debugger command. Multiline control structures can still be fragile; keep each `.if` or `.for` statement on one line. The same file can be invoked from `-c` at startup.<sup>[[1]](#references)[[8]](#references)</sup>

For logic that is awkward in command language, PyKD exposes typed structures, registers, memory, and debugger output to Python. For example, `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` accesses PEB fields, `pykd.loadBytes(address, size)` reads memory, and `pykd.dbgCommand("lm")` returns debugger output for parsing. Prefer bounded `loadChars`/`loadWChars` over unbounded string reads for possibly unterminated data. PyKD's `disasm(address).asm(instruction)` **writes assembled bytes at that address**, so preserve and restore the original memory if using it to obtain opcodes in a live process.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: Debugging - WinDBG(X) Automation & Scripting - Part 1](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx, sxd, sxe, sxi, sxn, sxr, sx- (Set Exceptions)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be (Breakpoint Enable)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd (Breakpoint Disable)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp, bu, bm (Set Breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Corelan trigscan source](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: WinDbg Command-Line Options](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: Run Script File](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
