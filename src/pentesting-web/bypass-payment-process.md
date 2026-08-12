# Bypass Payment Process

{{#include ../banners/hacktricks-training.md}}

## Payment Bypass Techniques

### Request Interception

Map the complete transaction state machine—cart, checkout session, payment-provider redirect, webhook/callback, order fulfillment, refund, and cancellation—and intercept every request in an authorized test account. The application must derive the paid amount, currency, order, and final status from trusted server-side state, not browser-controlled values.<sup>[[1]](#references)</sup>

- **Success**: This parameter often indicates the status of the transaction.
- **Referrer**: It might point to the source from where the request originated.
- **Callback**: This is typically used for redirecting the user after a transaction is completed.

### URL Analysis

If you encounter a parameter that contains a URL, especially one following the pattern _example.com/payment/MD5HASH_, it requires closer examination. Here's a step-by-step approach:

1. **Copy the URL**: Extract the URL from the parameter value.
2. **Independent inspection**: Open the copied URL in a separate browser profile and determine whether possession of the URL alone authorizes access, whether it expires, and whether it is bound to the correct user and order.

### Parameter Manipulation

1. **Change parameter values**: Alter values such as _Success_, _Referrer_, or _Callback_, and also test amount, currency, quantity, product/order ID, discount, and shipping fields. A client-side `false` to `true` change must never mark an order paid.
2. **Remove Parameters**: Try removing certain parameters altogether to see how the system reacts. Some systems might have fallbacks or default behaviors when expected parameters are missing.

### Cookie Tampering

1. **Examine Cookies**: Many websites store crucial information in cookies. Inspect these cookies for any data related to payment status or user authentication.
2. **Modify Cookie Values**: Alter the values stored in the cookies and observe how the website's response or behavior changes.

### Session Hijacking

1. **Session tokens**: Check whether checkout and payment tokens are unpredictable, short-lived, single-use, and bound to the correct user, cart, amount, and environment. Test replay and cross-account substitution only with engagement-owned accounts.

### Response Tampering

1. **Intercept Responses**: Use tools to intercept and analyze the responses from the server. Look for any data that might indicate a successful transaction or reveal the next steps in the payment process.
2. **Modify responses**: Change the browser-visible response to simulate success. This should affect only presentation; fulfillment must wait for a verified server-to-server result. Also replay, reorder, duplicate, and omit callbacks/webhooks to test idempotency and state transitions.<sup>[[1]](#references)</sup>

## References

- [1] [OWASP WSTG — Test Payment Functionality](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/10-Test-Payment-Functionality)

{{#include ../banners/hacktricks-training.md}}
