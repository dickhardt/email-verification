# EAV WG — Draft Charter

Revision 00-01 · 2026-11-20 · Revises 00-00, the text of [charter-ietf-evp-00-00](https://datatracker.ietf.org/doc/charter-ietf-evp/00-00/) presented at the IETF 127 BoF

Web and native applications verify that a user controls an email address by sending a message containing a one-time code or link, which the user retrieves from their mailbox and returns to the application. Many users abandon the flow at this step. Because the user carries the code, any site that asks for it can phish it. Because the message is sent from the application's domain, the email provider learns which application the user is interacting with.

Browser and mobile platform vendors addressed the same problem for SMS by binding one-time codes to the website or application they were issued for, so the platform can deliver the code and refuse to offer it anywhere else (W3C WICG Origin-bound One-time Codes Delivered via SMS, and the WebOTP API). Email has no equivalent.

A verified address gives an application a way to send mail to the user. It also gives the application an identifier, which applications that hold the same address can use to correlate the user. Many applications need only the first. A *global email address* is one the user gives to more than one application. A *directed email address* delivers to the user's mailbox and is given to only one web origin or application, so applications given different directed email addresses for the same user cannot correlate the user by address.

The Email Address Verification (EAV) working group will specify mechanisms that let a browser or operating system complete email address verification for web and native applications, without the user retrieving and re-entering a code.

## Scope

The WG's deliverables address verification of email addresses; the WG may discuss applicability to verification of related identifier systems.

The WG will consider approaches in which an email domain, or a party the domain delegates to, asserts to the browser or operating system that the user controls an address, and approaches in which a verification message carries the code in a machine-readable form bound to the requesting origin, so that the recipient's mail software can pass it to the browser or operating system. The WG may adopt other approaches that meet the goal above.

Mechanisms the WG specifies will support both global and directed email addresses, and the user chooses which one an application receives. A mechanism may issue a new directed email address during verification, and will support verifying the same directed email address when the user returns to the application.

In evaluating mechanisms, the WG will consider:

- resistance to phishing, by binding the result to the requesting web origin or application
- whether the email provider learns which application requested verification
- whether applications can correlate a user across applications by the verified address
- whether the mechanism reveals if an address exists
- support for native applications as well as web applications
- what email domains, mail clients, browsers, and operating systems must deploy
- how the verified address is represented to the application, including whether the application can tell a directed email address from a global one

The WG will use draft-hardt-email-verification and draft-goto-otp-token as starting points.

## Out of Scope

- Consent to receive messages at the address
- The browser API through which a web page requests verification, which the W3C WICG Email Verification API defines
- The user interface for choosing between a global and a directed email address
- Platform APIs for native applications, and mechanisms that associate an application with a web origin
- Interfaces between mail clients and browsers or operating systems
- How the user authenticates to their email provider
- Changes to SMTP (RFC 5321) or the Internet Message Format (RFC 5322); defining a new header field is not such a change
- How mail sent to a directed email address reaches the user's mailbox
- Changes to DKIM, SPF, or DMARC
- Equivalence rules for email addresses, which RFC 5321 leaves to the domain that hosts the mailbox
- General-purpose discovery of public keys for email addresses
- Attributes other than the email address
- How an application uses a verified address, such as for account recovery or as an authentication factor

## Deliverables

One or more Proposed Standard specifications defining mechanisms that meet the goal above

## Coordination

The WG will coordinate with the W3C WICG (Email Verification API, WebOTP), the W3C Federated Identity WG, W3C WebAppSec, WHATWG HTML, and the IETF MAILMAINT, DMARC, and DNSOP working groups.
