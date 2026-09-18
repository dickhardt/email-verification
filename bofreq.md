# Name: Email Address Verification (EAV)

## Description

Web and native applications verify that a user controls an email address by sending a one-time passcode (OTP) or a link. The user switches to a mail client, waits for delivery, finds the message, and re-enters the code. Many users abandon the flow at this step. Because the user carries the code by hand, any site that asks for it can phish it. The email provider also learns which application the user is signing up with, because the message is sent from the application's domain.

Phone number verification had the same problem. The W3C WICG specified origin-bound SMS one-time codes and the WebOTP API, and Apple and Android bind SMS codes to a website or an app so the platform can deliver the code and offer it nowhere else. Email has no equivalent.

This BoF proposes a working group to solve this for email, starting from two proposals. The Email Verification Protocol (EVP) lets the user's browser or operating system obtain an issuer-signed token that the user controls an address, with no message sent. The email domain delegates to the issuer through DNS, and the issuer does not learn which application asked. The OTP-Token email header field carries an origin-bound OTP in a machine-readable header, for email domains without an EVP issuer. The draft charter lets the WG evaluate and adopt other proposals that meet the same goals. The browser API is developed in the W3C WICG.

EVP was presented at DISPATCH at IETF 126 in Vienna, which recommended a BoF. The EVP side meeting at IETF 126 was well attended. EVP is in origin trials in Chrome and Edge, with Gmail operating an issuer. The session will present the problem, the drafts, and the prior SMS work, and discuss the draft charter.

## Required Details

- Status: WG forming
- Responsible AD: Andy Newton (ART)
- BOF proponents: Dick Hardt <dick.hardt@gmail.com>, Sam Goto <goto@google.com>
- Number of people expected to attend: 100
- Length of session (1 or usually 2 hours): 2 hours
- Conflicts (whole Areas and/or WGs)
  - Chair Conflicts: TBD
  - Technology Overlap: MAILMAINT, DMARC, OAUTH, HTTPBIS, DNSOP, WEBBOTAUTH
  - Key Participant Conflict: OAUTH, HTTPBIS, WEBBOTAUTH

## Information for IAB/IESG

- Protocols or practices that already exist in this space:
  - Email OTPs and magic links, with no standard format. Software that extracts codes does so by heuristics; macOS 26 offers AutoFill for codes it detects in Mail.
  - OpenID Connect returns `email` and `email_verified` claims, but requires an account with, and an integration for, each provider, and the provider learns every RP.
  - For SMS: W3C WICG Origin-bound one-time codes delivered via SMS and the WebOTP API, WHATWG HTML `autocomplete="one-time-code"`, Apple domain-bound codes, and the Android SMS Retriever API.
  - W3C FedID WG FedCM and the Login Status API, which the browser API uses for account discovery.
- Which (if any) modifications to existing protocols or practices are required:
  - Profiles of HTTP Message Signatures \[RFC9421\] and SD-JWT key binding, with no changes to either.
  - IANA registrations: `OTP-Token` in the Message Header Field Names registry \[RFC3864\], `_email-verification` in the Underscored and Globally Scoped DNS Node Names registry \[RFC8552\], `email-verification` in the Well-Known URIs registry \[RFC8615\], JWT claims, and the `application/evt+jwt` media type.
  - Outside the IETF: `autocomplete` tokens in WHATWG HTML and the `email-verification` Fetch destination.
  - Other proposals the WG adopts may require further modifications.
- Which (if any) entirely new protocols or practices are required:
  - EVP: issuer discovery through DNS, the token request, the EVT and KB-JWT formats, and private per-RP addresses.
  - The OTP-Token email header field.
- Open source projects (if any) implementing this work:
  - Chromium implements the browser side, used in the Chrome and Edge origin trials.
  - Other implementations: Gmail issuer (origin trial), Hellō issuer (exploratory).

## Agenda

- Chairs' introduction and agenda bash — 5 min
- Problem statement: verification friction, phishing, provider visibility — Dick Hardt, 15 min
- Prior work: origin-bound SMS codes and WebOTP — Sam Goto, 10 min
- Email Verification Protocol, draft-hardt-email-verification — Dick Hardt, 25 min
- OTP-Token email header field, [draft-goto-otp-token](https://datatracker.ietf.org/doc/draft-goto-otp-token/) — Sam Goto, 15 min
- Other proposals — open, 10 min
- W3C Email Verification API and origin trial results — Sam Goto, 10 min
- Charter discussion — chairs, 25 min
- BoF questions — chairs, 5 min
  - Is the problem understood and worth solving?
  - Is the IETF the right venue for the protocol work, with the browser API in the W3C?
  - Is the draft charter scoped correctly?
  - Are people willing to edit, review, and implement?
  - Should a WG be formed with this charter?

## Links to the mailing list, draft charter if any (for WG-forming BoF), relevant Internet-Drafts, etc.

- Mailing List: https://mailman3.ietf.org/mailman3/lists/evp-discuss.ietf.org/
- Draft charter: https://dickhardt.github.io/email-verification/charter-ietf-eav-00-00.html
- Relevant Internet-Drafts:
  - Solutions:
    - https://datatracker.ietf.org/doc/draft-hardt-email-verification/
    - https://datatracker.ietf.org/doc/draft-goto-otp-token/
  - Dependencies:
    - https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/
- Related W3C WICG specifications:
  - Email Verification API: https://wicg.github.io/email-verification/
  - Origin-bound one-time codes delivered via SMS: https://wicg.github.io/sms-one-time-codes/
  - WebOTP API: https://wicg.github.io/web-otp/
