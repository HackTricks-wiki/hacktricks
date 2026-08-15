# PDF Upload: XXE and Same-Origin Policy Bypass

{{#include ../../banners/hacktricks-training.md}}

PDF files can contain actions, forms, and references to external resources, so an upload feature may expose more than document-rendering risk. The linked research documents historical Adobe Reader issues involving external entities and a same-origin-policy bypass, often described as a **CORS bypass**. Treat its proof of concept as version-specific: reproduce it only with the affected reader and browser integration, and verify current behavior independently.<sup>[[1]](#references)</sup>

## References

- [1] [InsertScript - Multiple PDF Vulnerabilities: Text and Pictures on Steroids](https://insert-script.blogspot.com/2014/12/multiple-pdf-vulnerabilites-text-and.html)

{{#include ../../banners/hacktricks-training.md}}
