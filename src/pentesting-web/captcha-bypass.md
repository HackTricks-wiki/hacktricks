# Captcha Bypass

{{#include ../banners/hacktricks-training.md}}

## CAPTCHA bypass testing

During an authorized assessment, test whether the **server** actually binds a CAPTCHA solution to the intended action, session, challenge, and expiry. A CAPTCHA is a rate-abuse control, not a replacement for authorization, throttling, or account lockout.<sup>[[1]](#references)</sup>

1. **Parameter Manipulation**:
   - **Omit the Captcha Parameter**: Avoid sending the captcha parameter. Experiment with changing the HTTP method from POST to GET or other verbs, and altering the data format, such as switching between form data and JSON.
   - **Send Empty Captcha**: Submit the request with the captcha parameter present but left empty.
2. **Value Extraction and Reuse**:
   - **Source Code Inspection**: Search for the captcha value within the page's source code.
   - **Cookie Analysis**: Examine the cookies to find if the captcha value is stored and reused.
   - **Reuse Old Captcha Values**: Attempt to use previously successful captcha values again. Keep in mind that they might expire at any time.
   - **Session Manipulation**: Try using the same captcha value across different sessions or the same session ID.
3. **Automation and Recognition**:
   - **Mathematical Captchas**: If the captcha involves math operations, automate the calculation process.
   - **Image Recognition**:
     - For captchas that require reading characters from an image, manually or programmatically determine the total number of unique images. If the set is limited, you might identify each image by its MD5 hash.
     - Use OCR tools such as Tesseract to evaluate whether character challenges are machine-readable.<sup>[[2]](#references)</sup>
4. **Additional Techniques**:
   - **Rate Limit Testing**: Check if the application limits the number of attempts or submissions in a given timeframe and whether this limit can be bypassed or reset.
   - **Third-party Services**: Employ captcha-solving services or APIs that offer automated captcha recognition and solving.
   - **Session and IP rotation**: Determine whether limits are bound only to an IP address or session and whether rotating test-owned session IDs or authorized source IPs bypasses the control. Also test whether normal application flows reset the counter. Do not evade third-party controls outside the agreed test scope.
   - **User-Agent and Header Manipulation**: Alter the User-Agent and other request headers to mimic different browsers or devices.
   - **Audio Captcha Analysis**: If an audio captcha option is available, use speech-to-text services to interpret and solve the captcha.

## Online CAPTCHA-solving services

### [CapSolver](https://www.capsolver.com/?utm_source=google&utm_medium=ads&utm_campaign=scraping&utm_term=hacktricks&utm_content=captchabypass)

**CapSolver** is one example of a commercial API and browser-extension service that claims support for reCAPTCHA, DataDome, AWS CAPTCHA, GeeTest, and Cloudflare Turnstile. Its client options include extensions for [Chrome](https://chromewebstore.google.com/detail/captcha-solver-auto-captc/pgojnojmmhpofjgdmaebadhbocahppod) and [Firefox](https://addons.mozilla.org/firefox/addon/capsolver-captcha-solver/). Treat any external solver as a data processor: test only accounts and challenges covered by the engagement, and do not send sensitive screenshots, tokens, or production user data without approval.<sup>[[3]](#references)</sup>

{{#ref}}
https://www.capsolver.com/?utm_campaign=scraping&utm_content=captchabypass&utm_medium=ads&utm_source=google&utm_term=hacktricks
{{#endref}}

## References

- [1] [OWASP WSTG — Testing for Weak Lock Out Mechanism (CAPTCHA test cases)](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism)
- [2] [Tesseract OCR](https://github.com/tesseract-ocr/tesseract)
- [3] [CapSolver documentation](https://docs.capsolver.com/)

{{#include ../banners/hacktricks-training.md}}
