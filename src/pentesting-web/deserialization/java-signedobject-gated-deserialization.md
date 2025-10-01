# Java SignedObject-gated Deserialization and Pre-auth Reachability via Error Paths

{{#include ../../banners/hacktricks-training.md}}

This page documents a common "guarded" Java deserialization pattern built around java.security.SignedObject and how seemingly unreachable sinks can become pre-auth reachable via error-handling flows. The technique was observed in Fortra GoAnywhere MFT (CVE-2025-10035) but is applicable to similar designs.

## Threat model

- Attacker can reach an HTTP endpoint that eventually processes an attacker-supplied byte[] intended to be a serialized SignedObject.
- The code uses a validating wrapper (e.g., Apache Commons IO ValidatingObjectInputStream or a custom adapter) to constrain the outermost type to SignedObject (or byte[]).
- The inner object returned by SignedObject.getObject() is where gadget chains can trigger (e.g., CommonsBeanutils1), but only after a signature verification gate.

## Typical vulnerable pattern

A simplified example based on com.linoma.license.gen2.BundleWorker.verify:

```java
private static byte[] verify(byte[] payload, KeyConfig keyCfg) throws Exception {
    String sigAlg = "SHA1withDSA";
    if ("2".equals(keyCfg.getVersion())) {
        sigAlg = "SHA512withRSA";        // key version controls algorithm
    }
    PublicKey pub = getPublicKey(keyCfg);
    Signature sig = Signature.getInstance(sigAlg);

    // 1) Outer, "guarded" deserialization restricted to SignedObject
    SignedObject so = (SignedObject) JavaSerializationUtilities.deserialize(
        payload, SignedObject.class, new Class[]{ byte[].class });

    if (keyCfg.isServer()) {
        // Hardened server path
        return ((SignedContainer) JavaSerializationUtilities.deserializeUntrustedSignedObject(
            so, SignedContainer.class, new Class[]{ byte[].class }
        )).getData();
    } else {
        // 2) Signature check using a baked-in public key
        if (!so.verify(pub, sig)) {
            throw new IOException("Unable to verify signature!");
        }
        // 3) Inner object deserialization (potential gadget execution)
        SignedContainer inner = (SignedContainer) so.getObject();
        return inner.getData();
    }
}
```

Key observations:
- The validating deserializer at (1) blocks arbitrary top-level gadget classes; only SignedObject (or raw byte[]) is accepted.
- The RCE primitive would be in the inner object materialized by SignedObject.getObject() at (3).
- A signature gate at (2) enforces that the SignedObject must verify against a product-baked public key. Unless the attacker can produce a valid signature, the inner gadget never deserializes.

## Exploitation considerations

To achieve code execution, an attacker must deliver a correctly signed SignedObject that wraps a malicious gadget chain as its inner object. This generally requires one of the following:

- Private key compromise: obtain the matching private key used by the product to sign/verify license objects.
- Signing oracle: coerce the vendor or a trusted signing service to sign attacker-controlled serialized content (e.g., if a license server signs an embedded arbitrary object from client input).
- Alternate reachable path: find a server-side path that deserializes the inner object without enforcing verify(), or that skips signature checks under a specific mode.

Absent one of these, signature verification will prevent exploitation despite the presence of a deserialization sink.

## Pre-auth reachability via error-handling flows

Even when a deserialization endpoint appears to require authentication or a session-bound token, error-handling code can inadvertently mint and attach the token to an unauthenticated session.

Example reachability chain (GoAnywhere MFT):
- Target servlet: /goanywhere/lic/accept/<GUID> requires a session-bound license request token.
- Error path: hitting /goanywhere/license/Unlicensed.xhtml with trailing junk and invalid JSF state triggers AdminErrorHandlerServlet, which does:
  - SessionUtilities.generateLicenseRequestToken(session)
  - Redirects to vendor license server with a signed license request in bundle=<...>
- The bundle can be decrypted offline (hard-coded keys) to recover the GUID. Keep the same session cookie and POST to /goanywhere/lic/accept/<GUID> with attacker-controlled bundle bytes, reaching the SignedObject sink pre-auth.

Proof-of-reachability (impact-less) probe:

```http
GET /goanywhere/license/Unlicensed.xhtml/x?javax.faces.ViewState=x&GARequestAction=activate HTTP/1.1
Host: <target>
```

- Unpatched: 302 Location header to https://my.goanywhere.com/lic/request?bundle=... and Set-Cookie: ASESSIONID=...
- Patched: redirect without bundle (no token generation).

## Blue-team detection

Indicators in stack traces/logs strongly suggest attempts to hit a SignedObject-gated sink:

```
java.io.ObjectInputStream.readObject
java.security.SignedObject.getObject
com.linoma.license.gen2.BundleWorker.verify
com.linoma.license.gen2.BundleWorker.unbundle
com.linoma.license.gen2.LicenseController.getResponse
com.linoma.license.gen2.LicenseAPI.getResponse
com.linoma.ga.ui.admin.servlet.LicenseResponseServlet.doPost
```

## Hardening guidance

- Maintain signature verification before any getObject() call and ensure the verification uses the intended public key/algorithm.
- Replace direct SignedObject.getObject() calls with a hardened wrapper that re-applies filtering to the inner stream (e.g., deserializeUntrustedSignedObject using ValidatingObjectInputStream/ObjectInputFilter allow-lists).
- Remove error-handler flows that issue session-bound tokens for unauthenticated users. Treat error paths as attack surface.
- Prefer Java serialization filters (JEP 290) with strict allow-lists for both outer and inner deserializations. Example:

```java
ObjectInputFilter filter = info -> {
    Class<?> c = info.serialClass();
    if (c == null) return ObjectInputFilter.Status.UNDECIDED;
    if (c == java.security.SignedObject.class || c == byte[].class) return ObjectInputFilter.Status.ALLOWED;
    return ObjectInputFilter.Status.REJECTED; // outer layer
};
ObjectInputFilter.Config.setSerialFilter(filter);
// For the inner object, apply a separate strict DTO allow-list
```

## Example attack chain recap (CVE-2025-10035)

1) Pre-auth token minting via error handler:

```http
GET /goanywhere/license/Unlicensed.xhtml/watchTowr?javax.faces.ViewState=watchTowr&GARequestAction=activate
```

Receive 302 with bundle=... and ASESSIONID=...; decrypt bundle offline to recover GUID.

2) Reach the sink pre-auth with same cookie:

```http
POST /goanywhere/lic/accept/<GUID> HTTP/1.1
Cookie: ASESSIONID=<value>
Content-Type: application/x-www-form-urlencoded

bundle=<attacker-controlled-bytes>
```

3) RCE requires a correctly signed SignedObject wrapping a gadget chain. Researchers could not bypass signature verification; exploitation hinges on access to a matching private key or a signing oracle.

## Fixed versions and behavioural changes

- GoAnywhere MFT 7.8.4 and Sustain Release 7.6.3:
  - Harden inner deserialization by replacing SignedObject.getObject() with a wrapper (deserializeUntrustedSignedObject).
  - Remove error-handler token generation, closing pre-auth reachability.

## Notes on JSF/ViewState

The reachability trick leverages a JSF page (.xhtml) and invalid javax.faces.ViewState to route into a privileged error handler. While not a JSF deserialization issue, it’s a recurring pre-auth pattern: break into error handlers that perform privileged actions and set security-relevant session attributes.

## References

- [watchTowr Labs – Is This Bad? This Feels Bad — GoAnywhere CVE-2025-10035](https://labs.watchtowr.com/is-this-bad-this-feels-bad-goanywhere-cve-2025-10035/)
- [Fortra advisory FI-2025-012 – Deserialization Vulnerability in GoAnywhere MFT's License Servlet](https://www.fortra.com/security/advisories/product-security/fi-2025-012)

{{#include ../../banners/hacktricks-training.md}}