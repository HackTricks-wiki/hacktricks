# Privacy-Preserving Communications and Sharing

End-to-end encryption protects content. It does not automatically hide the account, phone number, contact graph, IP address, push token, notification preview, timing, file metadata or recipient behavior. Select a tool by the metadata it removes and the observers it introduces.

## Compare communication models

| Tool/model | Useful property | Remaining observers and limits |
|---|---|---|
| Signal | Mature E2EE; usernames can initiate contact without sharing number; sealed sender reduces service metadata | Phone number is required for registration; service, push provider, contacts and endpoints retain some observations |
| SimpleX | No global user identifier; per-contact queues; optional Tor transport | Relay timing/transport, push service, invitations and endpoints; newer/smaller ecosystem |
| Briar | Direct synchronization; Tor online; Bluetooth/Wi-Fi offline; no central message store | Contacts and endpoints; local radio observers; Android-focused; both sides must be available or use Mailbox |
| OnionShare | Direct file/receive/chat/site over a temporary onion service; no storage provider | Sender computer is the service; link bearer learns access; timing and endpoints remain |
| `age` encrypted file | Simple recipient-key encryption independent of transport | Transport sees sender/recipient/timing/size; filenames/archive metadata and endpoints remain |
| Ordinary email + TLS | Server-to-server channel encryption | Both mail providers can normally read content and retain routing/account metadata |

## Signal: private contact without number disclosure

Signal usernames can start a chat without revealing the user's phone number to the new contact, but a phone number remains required to register.<sup>[[1]](#references)</sup> Sealed sender is an incremental metadata protection, not resistance to all IP/timing correlation.<sup>[[2]](#references)</sup>

### Workflow

1. Install Signal from the official app store/project and update the OS first.
2. Register with a number you are lawfully entitled to use. Do not use rented SMS activations, another person's number or a provider account obtained with false identity.
3. In **Settings → Privacy → Phone Number**, set who can see the number and who can find the account by number according to the threat model.
4. Create a username for new-contact discovery. Share its exact link/QR through an already authenticated channel; usernames can change and are not the profile name.
5. Disable contact upload/permissions if convenience is not worth the linkage, and add contacts manually where the platform supports it.
6. Open the contact details and compare the safety number/QR over a second channel or in person before sensitive content.
7. Review linked devices, registration lock/PIN, notification previews, screen security, call relaying, disappearing-message defaults and backup behavior.
8. Send a non-sensitive test message and call. Inspect lock-screen, desktop, wearable and cloud-notification traces on both sides.
9. Treat a changed safety number or unexpected linked device as an investigation event, not an alert to dismiss automatically.

Do not mix a pseudonymous profile photo, bio, group membership or schedule with an identifying Signal context.

## SimpleX: per-contact connections without a global identifier

SimpleX routes messages through unidirectional queues and does not assign a network-wide user identifier. Its own policy still documents transport sessions, temporary server data, push-notification tradeoffs and endpoint responsibility.<sup>[[3]](#references)</sup>

### Workflow

1. Download a maintained client from the official project/store and verify the publisher. Use a dedicated OS/app profile when identities must not mix.
2. Create a **local** profile with a context-specific display name and image. Deleting the app without a backup can lose the profile and connections.
3. At first launch, choose notification mode deliberately. Instant mobile push can expose additional metadata to Apple/Google infrastructure.
4. Create a one-time invitation link for one contact. Transfer it through an authenticated channel; anyone who obtains a live invitation may try to use it.
5. After connecting, open contact details and compare the security code in person or over an independent verified channel.<sup>[[4]](#references)</sup>
6. Use an incognito per-group profile where supported instead of recycling the same profile across unrelated groups.
7. Configure the client's supported Tor transport if the local network/server should not see the direct IP. Confirm connection after the change; do not force an unsupported system proxy.
8. Review delivery receipts, link previews, calls, automatic downloads and database export/backup. Each changes metadata or endpoint exposure.
9. Test recovery on a spare isolated device without running duplicated live profile state; the project warns concurrent copies can disrupt conversations.

No global identifier does not prevent a contact from identifying the user through content, profile reuse, invitation delivery, timing or social graph.

## Briar: direct and disruption-resistant messaging

Briar synchronizes directly between devices, through Tor when online and through Bluetooth/Wi-Fi during local outages. The official threat model assumes only limited adversarial monitoring of short-range radio, so local wireless is not invisible.<sup>[[5]](#references)</sup>

### Workflow

1. Install from the official Briar distribution and verify the package source. Use a supported Android device with current security updates.
2. Create a local account with a unique context nickname and strong password. There is no password-reset path; test that the unlock secret is recoverable.
3. Add contacts face-to-face by scanning each other's QR codes when possible. This authenticates the contact and avoids sending a link through a correlatable channel.
4. In connectivity settings, enable only the transports needed: Tor/Internet, Wi-Fi and/or Bluetooth. Disable local radios when not required.
5. For asynchronous delivery, evaluate Briar Mailbox on a dedicated powered device; inventory and physically protect it like a message server.
6. Send a benign test while Internet is available, then test the planned outage path with Internet disabled in an owner-authorized location.
7. Inspect Android backups, notification previews, screenshots and exported content. Local encrypted storage is exposed when the endpoint is unlocked/compromised.
8. Remove lost contacts/devices and retire the whole context if physical custody or account password is compromised.

## OnionShare: direct temporary transfer

OnionShare runs an onion service on the sender/receiver's computer; files are not uploaded to a storage provider, and traffic is end-to-end encrypted inside Tor.<sup>[[6]](#references)</sup> The complete onion URL is a bearer capability and must be protected.

### GUI file-sharing workflow

1. Install OnionShare from its official signed distribution and Tor Browser on the recipient side.
2. Put **sanitized copies** of files in a dedicated staging directory. Do not point OnionShare at a personal home directory.
3. Open **Share Files**, add only the staged files, leave the private key/access protection enabled, and keep **Stop sharing after files have been sent** enabled for one recipient.
4. Start sharing and send the complete onion URL through an already authenticated E2EE channel. Do not paste it into email, issue trackers or public chats.
5. The recipient opens the URL in Tor Browser, verifies the expected filenames/size with the sender, and downloads.
6. Both sides compare a pre-agreed or separately delivered SHA-256 digest for integrity when the file itself is the security boundary.
7. Confirm OnionShare stopped after download; otherwise stop it manually and close the application.
8. Delete the staged copy according to retention policy and inspect OnionShare history/log settings for unintended filename disclosure.

### CLI workflow

The official CLI accepts files as positional arguments and stops after the default single completed share. On a host with the official CLI/Tor installed:

```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```

Deliver the resulting full URL securely. Do not add `--public`, `--no-autostop-sharing`, verbose filename logging or persistence unless the threat model explicitly requires the resulting exposure.<sup>[[7]](#references)</sup>

Treat received documents as hostile. Open them in a disposable VM/Dangerzone-style renderer rather than on the identity-bearing host.

## Encrypt a file independently with `age`

Transport-independent encryption is useful when a storage/email provider may see the object. It does not conceal sender, recipient, size, timing or filename unless those are handled separately.

### Recipient setup

```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```

Authenticate the public recipient string through a second channel. The sender then runs:

```bash
age -R recipient-public.txt -o package.tar.age package.tar
```

The recipient decrypts to a new path:

```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```

The official CLI warns that `-o` overwrites an existing output, so use a new directory and verify the digest/content before moving it.<sup>[[8]](#references)</sup> Never send the identity file with the ciphertext.

## Reproducible file-sanitization pipeline

Metadata stripping is format-specific. Preserve an encrypted original when authenticity, forensics or chain of custody matters; operate on a copy.

### JPEG example

```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
  -o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```

This follows ExifTool's safer JPEG guidance: blindly removing every tag may also remove color information.<sup>[[9]](#references)</sup> Then visually inspect pixels for faces, reflections, screens, landmarks and unique damage/noise patterns.

### Office/PDF workflow

1. Keep the editable original encrypted and offline from the publication context.
2. Remove comments, tracked changes, hidden slides/sheets, embedded files, personal templates and document properties in the authoring application.
3. Export a new PDF from a dedicated clean profile; do not “print” to a cloud printer.
4. Inspect with both format-aware tools and a disposable visual renderer:

```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```

5. Search the rendered output for names, paths, email addresses and revision text. Rasterization can remove active structures but harms accessibility/search and does not remove visible content or writing style.
6. Hash the final artifact and transfer **only** that copy through the publication compartment.

## Privacy Pass: anonymous authorization for service designers

Privacy Pass separates token **issuance** from **redemption**. An origin can learn that a client possesses an issuer-approved token without learning the client's specific issuance interaction. Reusing a token, unique metadata, timing or collusion can reintroduce linkability.<sup>[[10]](#references)</sup>

Safe deployment pattern:

1. Define the statement the token proves (for example, rate-limit eligibility), not a hidden global identity.
2. Use the standardized architecture and issuance protocols; do not implement blind-signature cryptography from scratch.
3. Separate issuer/attester and origin administration where the desired property requires it.
4. Minimize public/private token metadata and ensure anonymity sets are large enough.
5. Issue batches before use where supported so issuance time does not trivially match redemption time.
6. Redeem each token once, validate the origin-bound challenge, and delete expired token state.
7. Keep cookies, IP logging and application accounts from silently defeating the token privacy property.
8. Test whether issuer and origin logs can join a controlled issuance and redemption event using timing, metadata or unique errors.

Privacy Pass is an application feature, not something a user can bolt onto an arbitrary account.

## Communications verification checklist

- [ ] Contact/invitation/key was authenticated independently.
- [ ] Phone number, username, profile, group and contact-upload exposure is understood.
- [ ] Direct IP, relay, Tor, push-provider and local-radio observers are listed.
- [ ] Notification previews, wearables, linked desktops and backups were tested.
- [ ] Files were sanitized, encrypted if needed and opened in a disposable context.
- [ ] Recovery works without bridging unrelated identities.
- [ ] Logs, history and temporary share services have a shutdown/retention rule.

## References

- [1] [Signal — Phone Number Privacy and Usernames](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Privacy Policy and Conditions of Use](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Privacy and security guide](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — How it works](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Security Design](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Advanced Usage and CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — official CLI and usage](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — Safely removing metadata](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
