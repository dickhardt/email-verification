# EAV WG — Draft Charter

2026-09-18 · @DickHardt

## Working Group

| Field | Value |
| --- | --- |
| Name | Email Address Verification |
| Acronym | eav |
| Area | Applications and Real-Time (ART) |
| Responsible AD | Andy Newton |
| Mailing list | [evp-discuss@ietf.org](https://mailman3.ietf.org/mailman3/lists/evp-discuss.ietf.org/) |

## Problem Statement

The working group will develop mechanisms that let the user's browser or operating system complete email address verification for web and native applications, so the user does not retrieve a one-time passcode (OTP) from their mailbox and re-enter it.

Web and native applications verify that a user controls an email address by sending a message containing an OTP or a link. The user switches to a mail client, waits for delivery, finds the message (possibly in spam), and returns the code. Many users abandon the flow at this step.

The user acts as the messenger, so any site that asks for the code can phish it. The email provider also learns which relying party (RP) the user is interacting with, because the verification message is sent from the RP's domain.

## Prior Work: SMS One-Time Codes

Phone number verification had the same problem. Browser and platform vendors addressed it by binding the code to the website or app it was issued for, so software can deliver it and refuse to offer it anywhere else. The OTP-Token work applies that model to email.

| Specification | Venue or platform | Binding and delivery |
| --- | --- | --- |
| [Origin-bound one-time codes delivered via SMS](https://wicg.github.io/sms-one-time-codes/) | W3C WICG, Draft CG Report, March 2021 | The last line of the SMS is `@<top-level host> #<code>`, optionally followed by `@<embedded host>` for a cross-origin iframe. The browser offers the code only when the document's origin is same origin or same site with the bound host. |
| [WebOTP API](https://wicg.github.io/web-otp/) | W3C WICG, Draft CG Report, April 2021 | `navigator.credentials.get({otp: {transport: ["sms"]}})` resolves to an `OTPCredential` whose `code` the browser took from an origin-bound message. Controlled by the `otp-credentials` permissions policy feature. |
| [`autocomplete="one-time-code"`](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#attr-fe-autocomplete-one-time-code) | WHATWG HTML | Autofill field name marking an input as a one-time code field. |
| [Domain-bound codes](https://developer.apple.com/documentation/security/enabling-autofill-for-domain-bound-sms-codes) | Apple, iOS 14 and macOS Big Sur | Uses the WICG format. AutoFill offers the code in Safari when the site matches the bound domain, and in an app when the domain is one of the app's associated domains. Apps mark the field with `UITextContentType.oneTimeCode`. |
| [SMS Retriever API](https://developers.google.com/identity/sms-retriever/verify) | Android | The message includes an 11-character hash derived from the app's package name and signing certificate. The platform hands the message to that app without SMS read permission. |

WebOTP anticipates transports other than SMS and names email as one. The WICG SMS format mitigates phishing only; it does not address SMS spoofing, SIM swapping, or interception. macOS 26 already offers AutoFill for one-time codes detected in messages received by Mail.

Email gives the WG two things SMS does not: a header section users do not normally see, which can carry the binding and a high-entropy `token`, and sender authentication through DKIM and DMARC.

## Scope

The WG will start from two proposals, EVP and OTP-Token, described below. Neither depends on the other: an email domain can deploy either, both, or neither, and an RP falls back to sending a message when neither is available. The WG may also evaluate other proposals that let the user's browser or operating system verify an email address without the user retrieving an OTP, and adopt those that meet the goals of this charter.

### Email Verification Protocol (EVP)

No message is sent. An email domain delegates verification to an issuer through a DNS record. The browser or operating system authenticates to the issuer with the user's existing session and obtains an issuer-signed Email Verification Token (EVT) that carries its public key in a `cnf` claim. The browser or operating system presents the EVT to the RP with a Key Binding JWT (KB-JWT) bound to the RP's origin and an RP-supplied nonce.

The WG will specify:

- issuer discovery: the DNS delegation record, the issuer identifier, and the issuer metadata document
- the token request from the browser or operating system to the issuer, signed with HTTP Message Signatures \[RFC9421\], with a Content-Digest \[RFC9530\] over the request body
- the EVT and KB-JWT formats, compatible with SD-JWT key binding, and the verification procedures for the browser or operating system and the RP
- the KB-JWT audience when the RP is a native application, expressed through the application's association with a web origin
- private, per-RP email addresses that an issuer returns in place of the user's address
- error responses
- the set of email addresses the protocol can verify, including the treatment of internationalized addresses \[RFC6531\]

The protocol will not reveal the RP's identity to the issuer. An EVT+KB presented to one RP will not be accepted by another. Issuer responses will not reveal, by content or timing, whether an address exists.

An EVT asserts that the user controls the address. It does not assert that the address can receive mail.

The security considerations will analyze the reliance on DNS for delegation and state when RPs and email domains are expected to use DNSSEC \[RFC4033\].

### OTP-Token email header field

A sender places the OTP in a machine-readable header field bound to an origin \[RFC6454\], alongside the human-readable code in the message body. A recipient Mail User Agent (rMUA) \[RFC5598\] can pass the code to the browser or operating system, which offers it only to a web page or native application that matches the origin. A native application matches through its association with the origin, as with domain-bound SMS codes. This covers email domains that do not operate an EVP issuer.

The WG will specify the field's syntax as a Structured Field \[RFC9651\], its `origin` and `token` parameters, and its parsing rules, including header unfolding \[RFC5322\]. The optional `token` parameter carries a high-entropy value that lets an RP distinguish automated delivery from a code a user typed.

Recipients whose software does not process the field will see no change in how the human-readable code works.

## Out of Scope

- The browser API: how the user selects an address, how the RP supplies the nonce, and how the EVT+KB reaches the RP. The W3C Email Verification API defines these.
- Platform APIs through which native applications request verification, and platform mechanisms that associate an application with a web origin, such as Apple Associated Domains and Android Digital Asset Links.
- Interfaces between rMUAs and browsers or operating systems for passing an OTP.
- How the user authenticates to the issuer. The WG will define only how the issuer signals that authentication is required.
- Changes to SMTP, DKIM, SPF, or DMARC.
- Rules for email address equivalence or canonicalization.
- General discovery of public keys for email-address identifiers.
- Identity attributes other than the email address.
- RP policy on how a verified address is used, such as for account recovery or as an authentication factor.

## Coordination

The WG will keep EVP's issuer discovery and token request consistent with the [W3C WICG Email Verification API](https://github.com/WICG/email-verification), so a single issuer deployment serves both specifications. The two currently differ on the issuer well-known file and the token request format.

| Group | Topic |
| --- | --- |
| W3C WICG | Email Verification API, the companion browser API; WebOTP and origin-bound SMS codes, which an email transport extends |
| W3C FedID WG | FedCM and the Login Status API, used for account discovery |
| W3C WebAppSec | Credential Management, which WebOTP extends; Fetch Metadata and the `Sec-Fetch-Dest: email-verification` value |
| WHATWG HTML | `autocomplete` tokens, including `one-time-code` and `email-verification-token` |
| MAILMAINT | The OTP-Token header field |
| DMARC | Whether OTP-Token's `origin` is checked against a DMARC-aligned sender domain |
| DNSOP | The underscored DNS node name used for delegation |

The documents will request IANA registrations for:

- `_email-verification` in the Underscored and Globally Scoped DNS Node Names registry \[RFC8552\]
- `email-verification` in the Well-Known URIs registry \[RFC8615\]
- the `application/evt+jwt` media type
- new claims in the JSON Web Token Claims registry
- `OTP-Token` in the Message Header Field Names registry \[RFC3864\]

## Deliverables

| Document | Status | Starting point |
| --- | --- | --- |
| Email Verification Protocol | Proposed Standard | [draft-hardt-email-verification](https://dickhardt.github.io/email-verification/draft-hardt-email-verification.html) |
| The OTP-Token Email Header Field | Proposed Standard | [draft-goto-otp-token](https://datatracker.ietf.org/doc/draft-goto-otp-token/) |

The WG may adopt additional Proposed Standard documents for other proposals that meet the goals in the Scope section.

## Milestones

Targets are months after chartering.

| Month | Milestone |
| --- | --- |
| 2 | Adopt Email Verification Protocol as WG document |
| 2 | Adopt OTP-Token Email Header Field as WG document |
| 9 | WGLC on Email Verification Protocol |
| 9 | WGLC on OTP-Token Email Header Field |
| 12 | Submit OTP-Token Email Header Field to IESG |
| 12 | Submit Email Verification Protocol to IESG |
