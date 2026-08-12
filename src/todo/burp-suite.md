# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload types

Burp Intruder includes the following built-in payload generators and transformations:<sup>[[1]](#references)</sup>

- **Simple list:** Use a configured list of strings as payloads.
- **Runtime file:** Read one payload per line at runtime. This is useful for large lists because Burp does not load the entire file into memory.
- **Case modification:** Generate the unmodified value, lowercase and uppercase forms, `Propername` (first letter uppercase and the rest lowercase), or `ProperName` (first letter uppercase with the remaining characters unchanged). Burp discards duplicate results.
- **Numbers:** Generate sequential or random numbers within a configured range.
- **Brute forcer:** Generate every permutation for a chosen character set and minimum/maximum length.

## Extensions and companion tools

- **Collabfiltrator** generates payloads that execute commands and exfiltrate their output through DNS queries to Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** exports Burp findings for use in other reporting workflows.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** converts HTTP requests into scripts in several languages.<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger documentation - Burp Intruder payload types](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ../banners/hacktricks-training.md}}
