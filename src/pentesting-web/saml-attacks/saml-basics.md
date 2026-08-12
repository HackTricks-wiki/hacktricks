# SAML Basics

{{#include ../../banners/hacktricks-training.md}}

## SAML Overview

**Security Assertion Markup Language (SAML)** is an XML-based framework for exchanging assertions between an identity provider (IdP) and a service provider (SP). Assertions can carry authentication, attribute, and authorization-decision statements; the SAML 2.0 Web Browser SSO profile is commonly used to establish an SP session after the IdP authenticates the user.<sup>[[2]](#references)</sup>

### Comparison between SAML and OAuth

- **SAML 2.0** defines assertions, protocols, bindings, and profiles, including browser SSO. Messages and assertions are XML.
- **OAuth 2.0** is an authorization framework for delegated access; it is not an authentication protocol and does not require JSON tokens. **OpenID Connect** adds an identity layer and authentication semantics on top of OAuth 2.0.<sup>[[3]](#references)[[4]](#references)</sup>

## SAML Authentication Flow

**For further details check the full post from [https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/](https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/)**. This is a summary:<sup>[[1]](#references)</sup>

The flow below is the common **SP-initiated Web Browser SSO** profile using an HTTP-Redirect `AuthnRequest` and an HTTP-POST `Response`; SAML also supports other bindings and IdP-initiated flows.<sup>[[2]](#references)</sup>

![https://epi052.gitlab.io/notes-to-self/img/saml/saml-flow.jpg](https://epi052.gitlab.io/notes-to-self/img/saml/saml-flow.jpg)

1. **Resource Access Attempt**: The user tries to access a protected resource.
2. **SAML Request Generation**: The SP does not recognize the user and generates a SAML Request.
3. **Redirect to IdP**: The user is redirected to the IdP, with the SAML Request passing through the user's browser.
4. **IdP Receives Request**: The IdP receives the SAML Request.
5. **Authentication at IdP**: The IdP authenticates the user.
6. **User Validation**: The IdP validates the user's legitimacy to access the requested resource.
7. **SAML Response Creation**: The IdP generates a SAML Response containing necessary assertions.
8. **Redirect to SP's ACS URL**: The user is redirected to the SP's Assertion Consumer Service (ACS) URL.
9. **SAML Response Validation**: The ACS validates the SAML Response.
10. **Resource Access Granted**: Access to the initially requested resource is granted.

## SAML Request Example

Consider the scenario where a user requests access to a secure resource at [https://shibdemo-sp1.test.edu/secure/](https://shibdemo-sp1.test.edu/secure/). The SP identifies the lack of authentication and generates a SAML Request:

```
GET /secure/ HTTP/1.1
Host: shibdemo-sp1.test.edu
...
```

The raw SAML Request looks like this:

```xml
<?xml version="1.0"?>
<samlp:AuthnRequest ...
</samlp:AuthnRequest>
```

Key elements of this request include:

- **AssertionConsumerServiceURL**: Specifies where the IdP should send the SAML Response post-authentication.
- **Destination**: The IdP's address to which the request is sent.
- **ProtocolBinding**: Defines the transmission method of SAML protocol messages.
- **saml:Issuer**: Identifies the entity that initiated the request.

Following request generation, the SP responds with a **302 redirect** to the IdP. For the HTTP-Redirect binding, `SAMLRequest` is DEFLATE-compressed, base64-encoded, and URL-encoded in the `Location` query string. `RelayState` is opaque state returned by the IdP; the SP must bind or validate it before using it as a post-login destination to avoid open redirects or state confusion.<sup>[[1]](#references)[[2]](#references)</sup>

## SAML Response Example

You can find a [full SAML response here](https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/). The key components of the response include:<sup>[[1]](#references)</sup>

- **ds:Signature**: This section, an XML Signature, ensures the integrity and authenticity of the issuer of the assertion. The SAML response in the example contains two `ds:Signature` elements, one for the message and the other for the assertion.
- **saml:Assertion**: This part holds information about the user's identity and possibly other attributes.
- **saml:Subject**: It specifies the principal subject of all the statements in the assertion.
- **saml:StatusCode**: Represents the status of the operation in response to the corresponding request.
- **saml:Conditions**: Details conditions like the validity timing of the Assertion and the specified Service Provider.
- **saml:AuthnStatement**: Confirms that the IdP authenticated the subject of the Assertion.
- **saml:AttributeStatement**: Contains attributes describing the subject of the Assertion.

Following the SAML Response, the process includes a 302 redirect from the IdP. This leads to a POST request to the Service Provider's Assertion Consumer Service (ACS) URL. The POST request includes `RelayState` and `SAMLResponse` parameters. The ACS is responsible for processing and validating the SAML Response.

After the POST request is received and the SAML Response is validated, access is granted to the protected resource initially requested by the user. This is illustrated with a `GET` request to the `/secure/` endpoint and a `200 OK` response, indicating successful access to the resource.<sup>[[1]](#references)</sup>

## XML Signatures

XML Signatures are versatile, capable of signing an entire XML tree or specific elements within it. They can be applied to any XML Object, not just Response elements. Below are the key types of XML Signatures:<sup>[[1]](#references)</sup>

### Basic Structure of XML Signature

An XML Signature has the following simplified structure; `KeyInfo` is optional, `Object` may repeat, and `SignedInfo` contains one or more `Reference` elements.<sup>[[5]](#references)</sup>

```xml
<Signature>
  <SignedInfo>
    <CanonicalizationMethod />
    <SignatureMethod />
    <Reference>
       <Transforms />
       <DigestMethod />
       <DigestValue />
    </Reference>
    ...
  </SignedInfo>
  <SignatureValue />
  <KeyInfo />
  <Object />
</Signature>
```

Each `Reference` element signifies a specific resource being signed, identifiable by the URI attribute.

### Types of XML Signatures

1. **Enveloped Signature**: This type of signature is a descendant of the resource it signs, meaning the signature is contained within the same XML structure as the signed content.

   Example:

   ```xml
   <samlp:Response ... ID="..." ... >
       ...
       <ds:Signature>
           <ds:SignedInfo>
               ...
               <ds:Reference URI="#...">
                   ...
               </ds:Reference>
           </ds:SignedInfo>
       </ds:Signature>
       ...
   </samlp:Response>
   ```

   In an enveloped signature, the `ds:Transform` element specifies that it's enveloped through the `enveloped-signature` algorithm.

2. **Enveloping Signature**: The signed data is stored inside an `Object` element within the `Signature`, and a `Reference` identifies that object.<sup>[[5]](#references)</sup>

   Example:

   ```xml
   <ds:Signature>
       <ds:SignedInfo>
           ...
           <ds:Reference URI="#...">
               ...
           </ds:Reference>
       </ds:SignedInfo>
       <ds:Object Id="signed-object">
           <samlp:Response ... ID="..." ... >...</samlp:Response>
       </ds:Object>
   </ds:Signature>
   ```

3. **Detached Signature**: The signed content is outside the `Signature` element, either as a sibling in the same XML document or as an external resource identified by the reference URI.<sup>[[5]](#references)</sup>

   Example:

   ```xml
   <samlp:Response ... ID="..." ... >
       ...
   </samlp:Response>
   <ds:Signature>
       <ds:SignedInfo>
           ...
           <ds:Reference URI="#...">
               ...
           </ds:Reference>
       </ds:SignedInfo>
   </ds:Signature>
   ```

SAML implementations most commonly encounter enveloped signatures on the `Response` and/or `Assertion`. Validation must verify both the cryptographic signature and that the application consumes the exact element referenced by `SignedInfo`; merely finding a valid `Signature` somewhere in the document is insufficient.

## References

- [1] [How to test SAML: a methodology](https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/)
- [2] [OASIS - SAML V2.0 Technical Overview](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
- [3] [RFC 6749 - The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [4] [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [5] [W3C - XML Signature Syntax and Processing Version 1.1](https://www.w3.org/TR/xmldsig-core/)

{{#include ../../banners/hacktricks-training.md}}
