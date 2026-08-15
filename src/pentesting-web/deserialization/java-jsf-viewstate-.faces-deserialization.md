# Java JSF ViewState Deserialization

{{#include ../../banners/hacktricks-training.md}}

JavaServer Faces (JSF) may store view state in the client through the `javax.faces.ViewState` parameter. If the application accepts an unauthenticated serialized state without effective integrity protection, a crafted object graph can reach gadget classes on the server's classpath and lead to code execution during deserialization. Exploitability depends on the JSF implementation, its state-saving configuration, cryptographic protection, and available gadgets.<sup>[[1]](#references)</sup>

The first reference explains the affected configurations and mitigations. The second walks through a practical assessment in which exposed configuration material enabled a protected ViewState to be reproduced.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## References

- [1] [Misconfigured JSF ViewStates can lead to severe RCE vulnerabilities](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html)
- [2] [Arkham - Hack The Box writeup (0xRick)](https://0xrick.github.io/hack-the-box/arkham/)

{{#include ../../banners/hacktricks-training.md}}
