# Debugging Client-Side JavaScript

{{#include ../../banners/hacktricks-training.md}}

Client-side JavaScript debugging can become repetitive when navigation or parameter changes reload the page and invalidate temporary debugging state.

## `debugger;`

When developer tools are open, a `debugger;` statement pauses execution at that point unless breakpoints are disabled. Adding the statement to a persistent local copy is one way to keep the pause point across reloads.<sup>[[1]](#references)</sup>

## Overrides

Chrome DevTools Local Overrides stores a local replacement for a network resource and serves that replacement on subsequent page loads.<sup>[[2]](#references)</sup>

1. Open **DevTools > Sources > Overrides**.
2. Select an empty local folder and allow DevTools to access it.
3. In the **Page** tree, right-click the target script and select **Override content** or **Save for overrides**, depending on the Chrome version.
4. Add `debugger;`, save the file, and reload the page.

![Selecting a JavaScript file in the Sources panel and saving it as a local override](<../../images/image (742).png>)

The saved local copy now replaces the matching network resource while overrides are enabled. Changes therefore persist across reloads, but they affect only your local browser profile.<sup>[[2]](#references)</sup>

![A locally overridden JavaScript file containing a debugger statement](<../../images/image (594).png>)

The XSS challenge walkthrough in reference 3 demonstrates this `debugger;` and Local Overrides workflow during a practical client-side analysis.<sup>[[3]](#references)</sup>

## References

- [1] [Chrome for Developers - JavaScript debugging reference](https://developer.chrome.com/docs/devtools/javascript/reference)
- [2] [Chrome for Developers - Override web content and HTTP response headers locally](https://developer.chrome.com/docs/devtools/overrides/)
- [3] [YouTube - 4 hackers, one XSS challenge](https://www.youtube.com/watch?v=BW_-RCo9lo8&t=1529s)

{{#include ../../banners/hacktricks-training.md}}
