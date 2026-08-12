# Cookie Bomb

{{#include ../../banners/hacktricks-training.md}}

A cookie bomb fills a user's cookie jar with enough data that subsequent requests to a target origin carry an oversized `Cookie` header. If an intermediary or application rejects those requests, the affected user can be locked out of the site while other users remain unaffected. Broad cookie scope can extend the impact to related subdomains.<sup>[[1]](#references)[[2]](#references)</sup>

HackerOne report 57356 provides a practical example of this user-specific denial of service.<sup>[[1]](#references)</sup>

For broader background on cookie-based attacks and browser limits, see *The Cookie Monster in Your Browsers*.<sup>[[2]](#references)</sup>

## References

- [1] [HackerOne report 57356 - Cookie Bomb Denial of Service](https://hackerone.com/reports/57356)
- [2] [FileDescriptor - The Cookie Monster in Your Browsers](https://speakerdeck.com/filedescriptor/the-cookie-monster-in-your-browsers?slide=26)

{{#include ../../banners/hacktricks-training.md}}
