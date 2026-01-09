%%%
title = "Email Verification Protocol"
abbrev = "EVP"
ipr = "trust200902"
area = "Security"
workgroup = "TBD"
keyword = ["email", "verification", "identity", "authentication"]

[seriesInfo]
status = "standard"
name = "Internet-Draft"
value = "draft-hardt-email-verification-latest"
stream = "IETF"

date = 2026-01-06T00:00:00Z

[[author]]
initials = "D."
surname = "Hardt"
fullname = "Dick Hardt"
organization = "Hellō"
  [author.address]
  email = "dick.hardt@gmail.com"

[[author]]
initials = "S."
surname = "Goto"
fullname = "Sam Goto"
organization = "Google"
  [author.address]
  email = "goto@google.com"

%%%

<reference anchor="OpenID.Core" target="https://openid.net/specs/openid-connect-core-1_0.html">
  <front>
    <title>OpenID Connect Core 1.0</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization>NRI</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization>Ping Identity</organization>
    </author>
    <author initials="M." surname="Jones" fullname="Michael B. Jones">
      <organization>Microsoft</organization>
    </author>
    <author initials="B." surname="de Medeiros" fullname="Breno de Medeiros">
      <organization>Google</organization>
    </author>
    <author initials="C." surname="Mortimore" fullname="Chuck Mortimore">
      <organization>Salesforce</organization>
    </author>
    <date year="2014" month="November"/>
  </front>
</reference>

<reference anchor="WebAuthn" target="https://www.w3.org/TR/webauthn-3/">
  <front>
    <title>Web Authentication: An API for accessing Public Key Credentials - Level 3</title>
    <author initials="M." surname="Jones" fullname="Michael B. Jones">
      <organization>Microsoft</organization>
    </author>
    <author initials="A." surname="Kumar" fullname="Akshay Kumar">
      <organization>Microsoft</organization>
    </author>
    <author initials="E." surname="Lundberg" fullname="Emil Lundberg">
      <organization>Yubico</organization>
    </author>
    <date year="2023"/>
  </front>
  <seriesInfo name="W3C" value="Recommendation"/>
</reference>

<reference anchor="EVP-Browser" target="https://github.com/WICG/email-verification-protocol">
  <front>
    <title>Email Verification Protocol Browser API</title>
    <author>
      <organization>W3C</organization>
    </author>
    <date year="2025"/>
  </front>
</reference>

.# Abstract

This document defines the Email Verification Protocol (EVP), which enables web applications to verify that a user controls an email address without sending a verification email. The protocol uses a three-party model where the browser intermediates between the relying party and an issuer, providing both improved user experience and privacy protection.

.# Discussion Venues

*Note: This section is to be removed before publishing as an RFC.*

Source for this draft and an issue tracker can be found at https://github.com/dickhardt/email-verification.

The browser API aspects are being developed separately by the W3C ([@EVP-Browser]).

{mainmatter}

# Introduction

Web applications verify email addresses to send emails to users (transactional notifications, marketing, password resets) and to identify users (as a stable identifier for account creation and authentication). The standard verification method—sending a one-time code via email—has two problems: verification friction and privacy leakage.

## Verification Friction

The email one-time code flow requires the user to switch to their email client, wait for the message to arrive, find it (possibly in spam), read the code, return to the application, and enter it. Many users abandon this process before completing it.

Some approaches to reduce this friction:

- **Social login**: When a user has an account with Google, Apple, or another identity provider, the application can obtain a verified email without sending a verification message. However, this requires the user to have and use a social account, and requires developers to integrate with each provider separately.

- **Magic links**: Instead of a code, the verification email contains a link the user clicks to verify. This eliminates copying and pasting the code, but still requires switching to the email client, waiting for delivery, and finding the email.

## Privacy Leakage

Email verification creates two privacy problems:

1. **RP-to-RP correlation**: When a user provides their real email address to multiple relying parties (RPs), those RPs can correlate the user across sites by comparing email addresses.

2. **User-RP visibility**: The email provider learns which RPs the user visits and when. With email OTP, the provider sees verification emails from the sender and the delivery timing for every verification. With social login, the identity provider sees every RP request.

Reducing friction in email verification accelerates both privacy problems — users verify to more sites, increasing correlation potential and provider visibility.

## Friction Solution

The Email Verification Protocol (EVP) enables a web application to obtain a verified email address **without sending an email** and **without the user leaving the web page**. The browser intermediates between the RP and an issuer, obtaining a signed token that contains an email address for the user that the RP can verify. This eliminates the email delivery step entirely.

**Note on deliverability**: Like social login, this protocol verifies that the user controls an email address — it does not verify that the email address can receive mail.

## Privacy Solution

EVP addresses both privacy problems:

**Three-party model**: The browser intermediates between the RP and issuer, ensuring the issuer never learns which RP requested verification. See [Protocol Flow](#protocol-flow) for details.

**Private email addresses**: The browser can request a private email address instead of the user's actual email. Private addresses that differ per RP cannot be correlated across sites. See [Private Email Addresses](#private-email) for details.

# Protocol Flow

This document specifies the IETF protocol aspects of email verification: the HTTP-level interactions between the browser, issuer, and the application, aka relying party (RP). How the browser obtains the email address from the user (browser APIs, user interface elements, etc.) and how the browser communicates with the RP is being defined by the W3C ([@EVP-Browser]).

- **Issuer**: The service that verifies the user controls an email address. See [Issuer Discovery](#issuer-discovery) for how email domains delegate to issuers.

- **Three-party model**: The protocol uses a three-party model where the browser intermediates between the RP and issuer. The issuer issues a email verification token (EVT) to the browser containing the email address and the browser's key material—but not the RP identity. The browser then creates a key binding token (KB-JWT) that ties the EVT to a specific RP. The combined token (EVT+KB) is what the RP receives. This separation hides the RP from the issuer during verification.

The following diagram illustrates the protocol flow between the RP Server, Browser, and Issuer:

```
Step                      RP Server     Browser              Issuer
                               |            |                    |
2.1 Session Binding            |--- nonce ->|                    |
                               |            |                    |
2.2 Email Acquisition          |      [obtain email from user]   |
                               |            |                    |
2.3 Token Request              |            |-- POST /issuance ->|
                               |            |    (email, ...)    |
                               |            |                    |
2.4 EVT Creation               |            |           [create EVT]
                               |            |                    |
2.5 Token Issuance             |            |<------ EVT --------|
                               |            |                    |
2.6 KB Creation                |        [create KB-JWT]          |
                               |            |                    |
2.7 Token Presentation         |<-- EVT+KB -|                    |
                               |            |                    |
2.8 Token Verification    [verify EVT+KB]   |                    |
                               |            |                    |
```



## Session Binding {#session-binding}

The RP Server generates a cryptographically random nonce with at least 128 bits of entropy and binds it to a session it has with the browser. The nonce MUST be unique per verification request and SHOULD be valid for a limited time window. How the RP Server provides the nonce to the browser is being defined by the W3C ([@EVP-Browser]).

## Email Acquisition {#email-acquisition}

The browser obtains an email address from the user. This mechanism is being defined by the W3C ([@EVP-Browser]).

## Token Request {#token-request}

Once the browser has the email address and nonce:

1. The browser performs [Issuer Discovery](#issuer-discovery) for the email address to obtain the issuer's metadata, including the `issuance_endpoint`.

2. The browser generates a fresh private/public key pair. The browser SHOULD select an algorithm from the issuer's `signing_alg_values_supported` array, or use "EdDSA" if not present.

3. The browser creates a signed request per [HTTP Message Signatures](#http-signatures) and POSTs to the `issuance_endpoint`, including the issuer's cookies:

```http
POST /email-verification/issuance HTTP/1.1
Host: accounts.issuer.example
Cookie: session=...
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Sec-Fetch-Dest: email-verification
Signature-Input: sig=("@method" "@authority" "@path" \
    "content-digest" "cookie" "signature-key");created=1692345600
Signature: sig=:MEQCIHd8Y8qYKm5e3dV8y....:
Signature-Key: sig=hwk; kty="OKP"; crv="Ed25519"; \
    x="JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"

{"email":"user@example.com"}
```

## EVT Issuance {#evt-issuance}

On receipt of a token request:

1. The issuer verifies the request per [Request Verification](#request-verification).

2. The issuer checks if the cookies represent a logged-in user who controls the requested email address. If the issuer supports WebAuthn (`webauthn_supported: true`) and cookies are not present or invalid, the issuer MAY return a WebAuthn challenge (see [WebAuthn Authentication](#webauthn-authentication)).

3. If authentication succeeds, the issuer creates an EVT per [EVT Creation](#evt-creation) and returns it as the value of `issuance_token` in an `application/json` response:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"issuance_token":"eyJhbGciOiJFZERTQSIsImtpZCI6IjIwMjQtMDgtMTkiLCJ0eXAiOiJldnQrand0In0...~"}
```

## KB Creation {#kb-creation}

On receiving the `issuance_token`:

1. The browser verifies the EVT per [EVT Verification](#evt-verification), additionally confirming:
   - The `email` claim matches the email address being verified
   - The `cnf.jwk` claim matches the public key the browser generated

2. The browser creates a KB-JWT per [KB-JWT Creation](#kb-creation-detail), binding the EVT to the RP's origin and session nonce.

3. The browser concatenates the EVT and KB-JWT to form the EVT+KB.

Example EVT+KB (line breaks for display):
```
eyJhbGciOiJFZERTQSIsImtpZCI6IjIwMjQtMDgtMTkiLCJ0eXAiOiJldnQrand0In0.
eyJpc3MiOiJpc3N1ZXIuZXhhbXBsZSIsImlhdCI6MTcyNDA4MzIwMCwiY25mIjp7...}.
signature~
eyJhbGciOiJFZERTQSIsInR5cCI6ImtiK2p3dCJ9.
eyJhdWQiOiJodHRwczovL3JwLmV4YW1wbGUiLCJub25jZSI6IjI1OWM1ZWFlLTQ4...}.
signature
```

## Token Presentation {#token-presentation}

The browser provides the EVT+KB to the RP. This mechanism is being defined by the W3C ([@EVP-Browser]).

## Token Verification {#token-verification}

The RP receives the EVT+KB and verifies it by:

1. Verifying the KB-JWT per [KB-JWT Verification](#kb-verification)
2. Verifying the EVT per [EVT Verification](#evt-verification)
3. Verifying the KB-JWT signature using the public key from the EVT's `cnf.jwk` claim

If all verification steps pass, the RP has successfully verified that the user controls the email address in the `email` claim.


# Issuer Discovery {#issuer-discovery}

Both the browser and the RP need to discover information about the issuer for a given email address. This section describes the discovery process.

## DNS Delegation {#dns-delegation}

The email domain delegates email verification to an issuer via a DNS TXT record. Given an email address, parse the email domain ($EMAIL_DOMAIN) and look up the `TXT` record for `_email-verification.$EMAIL_DOMAIN`. The contents of the record MUST start with `iss=` followed by the issuer identifier. There MUST be only one `TXT` record for `_email-verification.$EMAIL_DOMAIN`.

Example record:

```bash
_email-verification.email-domain.example   TXT   iss=issuer.example
```

This record states that `email-domain.example` has delegated email verification to the issuer `issuer.example`.

If the email domain and the issuer are the same domain, then the record would be:

```bash
_email-verification.issuer.example   TXT   iss=issuer.example
```

> Access to DNS records and email is often independent of website deployments. This provides assurance that an issuer is truly authorized as an insider with only access to websites on `issuer.example` could not setup an issuer that would grant them verified emails for any email at `issuer.example`.

## Issuer Metadata {#issuer-metadata}

Once the issuer identifier is known, fetch the metadata document from `https://$ISSUER/.well-known/email-verification`. The request MUST follow redirects to the same path but with a different subdomain of the Issuer.

For example, `https://issuer.example/.well-known/email-verification` may redirect to `https://accounts.issuer.example/.well-known/email-verification`.

The metadata document is JSON containing the following properties:

- *issuance_endpoint* - the API endpoint the browser calls to obtain an EVT
- *jwks_uri* - the URL where the issuer provides its public keys to verify the EVT
- *signing_alg_values_supported* - OPTIONAL. JSON array containing a list of the signing algorithms ("alg" values) supported by the issuer for both HTTP Message Signatures and issued EVTs. Algorithm identifiers MUST be from the IANA "JSON Web Signature and Encryption Algorithms" registry. If omitted, "EdDSA" is the default. "EdDSA" SHOULD be included in the supported algorithms list. The value "none" MUST NOT be used.
- *webauthn_supported* - OPTIONAL. Boolean indicating whether the issuer supports WebAuthn authentication as an alternative to cookies. If `true`, the issuer may return a WebAuthn challenge when cookies are not present or invalid. Defaults to `false`.
- *private_email_supported* - OPTIONAL. Boolean indicating whether the issuer supports generating private email addresses. Defaults to `false`.

> **Open Question**: Should URL properties be required to include the issuer domain as the root of their hostname?

Following is an example `.well-known/email-verification` file:

```json
{
  "issuance_endpoint": "https://accounts.issuer.example/email-verification/issuance",
  "jwks_uri": "https://accounts.issuer.example/email-verification/jwks",
  "signing_alg_values_supported": ["EdDSA", "RS256"],
  "webauthn_supported": true,
  "private_email_supported": true
}
```


# HTTP Message Signatures {#http-signatures}

This section defines how HTTP Message Signatures ([@!RFC9421]) are used in token requests. The browser signs requests to prove possession of a key pair, and the issuer verifies these signatures.

## Request Signing {#request-signing}

The browser creates a signed request by:

1. Creating a JSON request body with the email address and optional parameters
2. Computing the `Content-Digest` header per [@!RFC9530] using SHA-256
3. Creating the `Signature-Key` header using the `hwk` scheme ([@!I-D.hardt-httpbis-signature-key]) with the browser's public key
4. Creating the `Signature-Input` header specifying the covered components
5. Computing the signature base per [@!RFC9421] Section 2.5 and signing with the browser's private key
6. Creating the `Signature` header with the base64-encoded signature

### Request Body

The request body is a JSON object with the following fields:

- `email` (REQUIRED): The email address to verify
- `disposable` (OPTIONAL): Request a private email address. See [Private Email Addresses](#private-email).
- `directed_email` (OPTIONAL): Identifier for a previously issued private email address. See [Private Email Addresses](#private-email).

Example:
```json
{
  "email": "user@example.com"
}
```

### Signature-Key Header

The `Signature-Key` header uses the `hwk` scheme to convey the browser's public key:

```
Signature-Key: sig=hwk; kty="OKP"; crv="Ed25519"; \
    x="JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
```

### Signature-Input Header

The covered components MUST include `@method`, `@authority`, `@path`, `content-digest`, and `signature-key`. The `cookie` component MUST be included when the Cookie header is present, and MUST be omitted when it is not (per [@!RFC9421] Section 2.5). The `created` parameter MUST be included.

```
Signature-Input: sig=("@method" "@authority" "@path" \
    "content-digest" "cookie" "signature-key");created=1692345600
```

### Example Signed Request

```http
POST /email-verification/issuance HTTP/1.1
Host: accounts.issuer.example
Cookie: session=...
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Sec-Fetch-Dest: email-verification
Signature-Input: sig=("@method" "@authority" "@path" \
    "content-digest" "cookie" "signature-key");created=1692345600
Signature: sig=:MEQCIHd8Y8qYKm5e3dV8y....:
Signature-Key: sig=hwk; kty="OKP"; crv="Ed25519"; \
    x="JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"

{"email":"user@example.com"}
```

## Request Verification {#request-verification}

The issuer MUST verify the request headers:

- `Content-Type` is `application/json`
- `Sec-Fetch-Dest` is `email-verification`
- `Content-Digest` is present
- `Signature-Input` is present
- `Signature` is present
- `Signature-Key` is present with `sig=hwk` scheme

The issuer MUST verify the HTTP Message Signature by:

1. Parsing the `Signature-Key` header and extracting the public key from the `hwk` parameters (`kty`, `crv`, `x` for OKP keys)
2. Parsing the `Signature-Input` header to determine the covered components
3. Verifying that the signature covers at minimum: `@method`, `@authority`, `@path`, `content-digest`, and `signature-key`. The signature MUST also cover `cookie` when the Cookie header is present.
4. Reconstructing the signature base per [@!RFC9421] Section 2.5
5. Verifying the signature in the `Signature` header using the extracted public key
6. Verifying the `created` timestamp in `Signature-Input` is within 60 seconds of the current time

The issuer MUST verify the request body:

1. Parsing the JSON body and extracting the `email` field
2. Verifying the `email` field contains a syntactically valid email address
3. Verifying the `Content-Digest` matches the actual request body


# Email Verification Token (EVT) {#evt}

The Email Verification Token (EVT) is a JWT issued by the issuer that contains a verified email address and the browser's public key. This section defines the EVT structure and how it is created and verified.

## EVT Structure {#evt-structure}

The EVT is a JWT with the following structure:

### Header

- `alg` (REQUIRED): Signing algorithm
- `kid` (REQUIRED): Key identifier of the key used to sign
- `typ` (REQUIRED): Set to "evt+jwt"

Example:
```json
{
  "alg": "EdDSA",
  "kid": "2024-08-19",
  "typ": "evt+jwt"
}
```

### Payload

Required claims:

- `iss`: The issuer identifier
- `iat`: Issued at time (seconds since epoch)
- `cnf`: Confirmation claim containing the browser's public key in `jwk` format (for SD-JWT Key Binding compatibility)
- `email`: The verified email address
- `email_verified`: Boolean, MUST be `true`

Optional claims:

- `is_private_email`: Boolean, set to `true` when the email is a private address

Example:
```json
{
  "iss": "issuer.example",
  "iat": 1724083200,
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
    }
  },
  "email": "user@example.com",
  "email_verified": true
}
```

### Format

The EVT has a `~` appended to it for SD-JWT compatibility (see [SD-JWT Compatibility](#sd-jwt-compatibility)).

## EVT Creation {#evt-creation}

After verifying the request (see [Request Verification](#request-verification)) and authenticating the user, the issuer creates the EVT:

1. Construct the header with `alg`, `kid`, and `typ`
2. Construct the payload with `iss`, `iat`, `cnf` (containing the public key from the `Signature-Key` header), `email`, and `email_verified`
3. If a private email is requested, include `is_private_email: true` and set `email` to the private address
4. Sign the JWT with the issuer's private key corresponding to the `kid`
5. Append `~` to the signed JWT

> Note: The `is_private_email` claim name matches Apple's Sign in with Apple for compatibility with existing RP implementations.

## EVT Verification {#evt-verification}

Both the browser and RP verify the EVT. The verification steps are:

1. Parse the EVT into header, payload, and signature components
2. Extract and validate the `alg` and `kid` from the header
3. Extract and validate the `iss`, `iat`, `cnf`, `email`, and `email_verified` claims from the payload
4. Perform [Issuer Discovery](#issuer-discovery) for the email domain to verify the `iss` claim matches the issuer identifier
5. Fetch the issuer's public keys from the `jwks_uri` in the issuer metadata
6. Verify the EVT signature using the public key identified by `kid`
7. Verify `iat` is within an acceptable time window
8. Verify `email_verified` is `true`

The browser additionally verifies:

- The `email` claim matches the email address being verified
- The `cnf.jwk` claim matches the public key the browser generated


# Key Binding (EVT+KB) {#kb}

Key Binding ties an EVT to a specific RP and session through a Key Binding JWT (KB-JWT). The combined EVT+KB is what the RP receives and verifies.

## KB-JWT Structure {#kb-structure}

The KB-JWT is a JWT with the following structure:

### Header

- `alg` (REQUIRED): Signing algorithm (same as the browser's key pair)
- `typ` (REQUIRED): Set to "kb+jwt" for SD-JWT library compatibility

Example:
```json
{
  "alg": "EdDSA",
  "typ": "kb+jwt"
}
```

### Payload

- `aud` (REQUIRED): The RP's origin
- `nonce` (REQUIRED): The nonce from the RP's session
- `iat` (REQUIRED): Issued at time
- `sd_hash` (REQUIRED): SHA-256 hash of the EVT for SD-JWT library compatibility

Example:
```json
{
  "aud": "https://rp.example",
  "nonce": "259c5eae-486d-4b0f-b666-2a5b5ce1c925",
  "iat": 1724083260,
  "sd_hash": "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
}
```

## EVT+KB Format {#evt-kb-format}

The EVT+KB is formed by concatenating the EVT and KB-JWT separated by a tilde:

```
<EVT>~<KB-JWT>
```

The EVT already has a trailing `~` from its SD-JWT format, so the full structure is:

```
<JWT>~<KB-JWT>
```

## SD-JWT Compatibility {#sd-jwt-compatibility}

The EVT+KB format is compatible with SD-JWT with Key Binding as specified in [@!I-D.ietf-oauth-selective-disclosure-jwt], though this protocol does not use selective disclosure features. The following SD-JWT features are used:

- **Trailing `~` on EVT**: The EVT uses the SD-JWT format (JWT with `~` suffix)
- **`cnf` claim**: The EVT includes the `cnf` claim with `jwk` for holder key binding
- **`typ: "kb+jwt"`**: The KB-JWT uses the SD-JWT Key Binding JWT type
- **`sd_hash` claim**: The KB-JWT includes the SD-JWT hash of the EVT
- **Concatenation format**: The EVT+KB uses the SD-JWT `<Issuer-signed-JWT>~<KB-JWT>` format

Standard SD-JWT libraries can be used to parse and validate EVT+KB tokens.

## KB-JWT Creation {#kb-creation-detail}

After verifying the EVT (see [EVT Verification](#evt-verification)), the browser creates the KB-JWT:

1. Construct the header with `alg` and `typ`
2. Construct the payload with:
   - `aud`: The RP's origin
   - `nonce`: The nonce from the RP's session
   - `iat`: Current time
   - `sd_hash`: SHA-256 hash of the EVT (including the trailing `~`)
3. Sign the KB-JWT with the browser's private key
4. Concatenate with the EVT to form the EVT+KB

## KB-JWT Verification {#kb-verification}

The RP verifies the KB-JWT by:

1. Parse the EVT+KB by separating at the tilde
2. Parse the KB-JWT into header, payload, and signature
3. Extract `alg` from the header and `aud`, `nonce`, `iat`, `sd_hash` from the payload
4. Verify `aud` matches the RP's origin
5. Verify `nonce` matches the nonce from the RP's session
6. Verify `iat` is within a reasonable time window
7. Compute the SHA-256 hash of the EVT and verify it matches `sd_hash`
8. Verify the KB-JWT signature using the public key from the EVT's `cnf.jwk` claim


# WebAuthn Authentication {#webauthn-authentication}

When the issuer supports WebAuthn (`webauthn_supported: true` in metadata) and a token request lacks valid authentication cookies, the issuer MAY return a WebAuthn challenge to authenticate the user. This enables email verification even when the user is not logged into the issuer via cookies, using any WebAuthn-compatible credential (passkeys, security keys, platform authenticators).

## WebAuthn Challenge Response

Instead of returning an error or an EVT, the issuer returns a WebAuthn challenge:

**HTTP 401 Unauthorized**
```json
{
  "webauthn_challenge": {
    "challenge": "dGVzdC1jaGFsbGVuZ2UtZGF0YQ",
    "timeout": 60000,
    "rpId": "issuer.example",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "Y3JlZGVudGlhbC1pZA"
      }
    ],
    "userVerification": "preferred"
  }
}
```

The `webauthn_challenge` object follows the structure of PublicKeyCredentialRequestOptions as defined in [@WebAuthn].

## WebAuthn Response

After the browser obtains a WebAuthn assertion (this mechanism is being defined by the W3C ([@EVP-Browser])), it sends a new request to the issuance endpoint with the `webauthn_response`:

```http
POST /email-verification/issuance HTTP/1.1
Host: accounts.issuer.example
Content-Type: application/json
Content-Digest: sha-256=:...:
Sec-Fetch-Dest: email-verification
Signature-Input: sig=("@method" "@authority" "@path" "content-digest" "signature-key");created=1692345600
Signature: sig=:...:
Signature-Key: sig=hwk; kty="OKP"; crv="Ed25519"; x="JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"

{
  "email": "user@example.com",
  "webauthn_response": {
    "id": "Y3JlZGVudGlhbC1pZA",
    "rawId": "Y3JlZGVudGlhbC1pZA",
    "response": {
      "authenticatorData": "...",
      "clientDataJSON": "...",
      "signature": "..."
    },
    "type": "public-key"
  }
}
```

The `webauthn_response` object follows the structure of PublicKeyCredential as defined in [@WebAuthn].

> Note: The WebAuthn request omits `cookie` from the signature components because WebAuthn authentication is used when the user lacks valid authentication cookies.

## WebAuthn Verification

The issuer verifies the WebAuthn response against its stored credentials for the email address. If verification succeeds, the issuer returns the EVT as described in [Token Issuance](#token-issuance).


# Private Email Addresses {#private-email}

Private email addresses allow users to provide site-specific email addresses to RPs, preventing RP-to-RP correlation of users by email address. There are two modes:

- **Disposable**: A new private email address is generated for each request
- **Directed**: A previously issued private email address is reused for account continuity

## Request Parameters

The token request body supports the following parameters for private email addresses:

- `disposable` (OPTIONAL): Boolean. When set to `true`, requests a new private email address instead of the user's actual email.

- `directed_email` (OPTIONAL): String. An opaque identifier for a previously issued private email address. When provided along with `disposable: true`, the issuer returns the same private email address if the identifier is valid and linked to the `email` in the request.

## Example Requests

Request for a new private email address (disposable):

```json
{
  "email": "user@example.com",
  "disposable": true
}
```

Request to reuse a previously issued private email address (directed):

```json
{
  "email": "user@example.com",
  "disposable": true,
  "directed_email": "d8f3a2b1-9c4e-4f6a-8b7d-1e2f3a4b5c6d"
}
```

## Requirements

- The private email MUST be a valid email address that the issuer can route to the user's actual mailbox
- The private email SHOULD be unique per user and per RP origin (derived from the browser's context)
- If `directed_email` is provided and is linked to the `email` address in the request, the issuer MUST return the same private email address
- If `directed_email` is not provided or is invalid, the issuer generates a new private email address
- The private email address is included in the EVT `email` claim
- The EVT MUST include `is_private_email: true` when a private email address is issued

## Issuer Flexibility

The domain of the private email address does not need to match the domain of the user's actual email address. Additionally, the `iss` claim in the EVT corresponds to the issuer for the private email domain, which may differ from the issuer the browser initially contacted.

For example, a user with `user@example.com` may receive a private email address `u7x9k2m4@privaterelay.different.example`. The EVT's `iss` claim would be the issuer for `privaterelay.different.example`. The browser verifies the EVT by performing issuer discovery on the private email domain and validating the signature against that issuer's JWKS. This allows email providers to delegate private email functionality to a separate service.

## Example EVT Payload

When a private email is issued, the EVT contains the private address in the `email` claim and includes `is_private_email: true`:

```json
{
  "iss": "privaterelay.different.example",
  "iat": 1724083200,
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
    }
  },
  "email": "u7x9k2m4@privaterelay.different.example",
  "email_verified": true,
  "is_private_email": true
}
```

The browser MAY store the `directed_email` identifier so it can provide it in future requests if the user wants to reuse the same private email address at an RP.

See [Privacy Considerations](#privacy-considerations) for privacy analysis of private email addresses.

# Error Responses

If the issuer cannot process the token request successfully, it MUST return an appropriate HTTP status code with a JSON error response containing an `error` field and optionally an `error_description` field.

## Invalid Content-Type Header

When the request does not include the required `Content-Type: application/json` header, the server MUST return the 415 HTTP response code.

## Invalid Sec-Fetch-Dest Header

When the request does not include the required `Sec-Fetch-Dest: email-verification` header:

**HTTP 400 Bad Request**
```json
{
  "error": "invalid_request",
  "error_description": "Missing or invalid Sec-Fetch-Dest header"
}
```

The `error_description` SHOULD specify that the Sec-Fetch-Dest header is missing or invalid.

## Invalid or Missing HTTP Message Signature

When the HTTP Message Signature is missing, malformed, or verification fails:

**HTTP 400 Bad Request**
```json
{
  "error": "invalid_signature",
  "error_description": "HTTP Message Signature verification failed"
}
```

This includes cases where:
- The `Signature`, `Signature-Input`, or `Signature-Key` headers are missing
- The `Signature-Key` header does not use the `hwk` scheme or is malformed
- The signature does not cover the required components
- The signature verification fails using the public key from `Signature-Key`
- The `created` timestamp is outside the acceptable time window

## Invalid Content-Digest

When the `Content-Digest` header is missing or does not match the request body:

**HTTP 400 Bad Request**
```json
{
  "error": "invalid_request",
  "error_description": "Content-Digest header missing or does not match request body"
}
```

## Authentication Required

When the request lacks valid authentication cookies, contains expired/invalid cookies, or the authenticated user does not have control of the requested email address:

**HTTP 401 Unauthorized**
```json
{
  "error": "authentication_required",
  "error_description": "User must be authenticated and have control of the requested email address"
}
```

## Invalid Parameters

When the request body is malformed, missing the `email` field, or contains invalid values:

**HTTP 400 Bad Request**
```json
{
  "error": "invalid_request",
  "error_description": "Invalid or malformed request body"
}
```

## Private Email Not Supported

When the request includes `disposable: true` but the issuer does not support private email addresses (`private_email_supported` is `false` or absent in metadata):

**HTTP 400 Bad Request**
```json
{
  "error": "private_email_not_supported",
  "error_description": "This issuer does not support private email addresses"
}
```

## Server Errors

For internal server errors or temporary unavailability:

**HTTP 500 Internal Server Error**
```json
{
  "error": "server_error",
  "error_description": "Temporary server error, please try again later"
}
```

# Privacy Considerations

This section analyzes the privacy properties of the Email Verification Protocol, following the guidance in [@?RFC6973].

## Reduced Friction Tradeoff

By reducing friction in email verification, EVP makes it easier for users to provide their email address to more sites. This convenience could accelerate the RP correlation problem—users may share a correlatable identifier with more RPs than they would if verification required more effort.

EVP addresses this tradeoff through private email addresses. When supported by the issuer, users can present a site-specific private email that cannot be correlated across RPs. This makes sharing a non-correlatable identifier just as easy as sharing the user's real email address, giving users a privacy-preserving option without additional friction.

## Timing Correlation by Email Providers

The three-party model (see [Protocol Flow](#protocol-flow)) prevents the issuer from learning which RP requested verification. When the RP uses the email only for identification and does not send emails, the email provider never learns about the RP at all. When the RP does send emails, the provider eventually learns about that RP, but only when email is actually sent—not at verification time. This dulls timing correlation.

## RP Correlation via Email Addresses

Private email addresses prevent RPs from correlating users across sites. Additional benefits:

**Protection from data breaches**: If an RP suffers a data breach, only the private email is exposed—not the user's primary email address.

**Protection from unwanted email**: Because the issuer controls private email routing, users can revoke or filter mail to specific addresses without affecting their primary inbox.

## Issuer Knowledge

The issuer learns certain information through the protocol:

1. **Email addresses**: The issuer learns that the user controls the email address in the request. This may reveal email addresses at domains the issuer is authoritative for that it did not previously know the user had.

2. **Verification requests**: The issuer sees that verification was requested but does not learn which RP requested it (maintained by the three-party model).

3. **Private email mappings**: When generating private emails, the issuer stores mappings between private addresses and user email addresses for mail routing.

4. **Email traffic**: When RPs send email to private addresses, the issuer (operating the relay) learns about those communications.

## RP Knowledge

The RP can infer whether the user is logged into the issuer: the RP receives an EVT when the user is logged in, and receives an error when the user is not. This is inherent to any authentication-based verification scheme.

## Browser Storage

The browser MAY store the `directed_email` identifier per RP origin to enable account continuity with private email addresses.

# Security Considerations

## HTTP Message Signature Security

The use of HTTP Message Signatures ([@!RFC9421]) provides several security benefits:

1. **Request Integrity**: The signature covers the HTTP method, target URI, authority, content-digest, cookies, and security headers, preventing tampering with any of these components.

2. **Cookie Binding**: By including the `cookie` component in the signature, the browser's authentication cookies are cryptographically bound to the specific request, preventing cookie injection or manipulation attacks.

3. **Replay Protection**: The `created` timestamp in the `Signature-Input` header is verified to be within 60 seconds, preventing replay attacks.

4. **Public Key Binding**: The browser's public key transmitted via the `Signature-Key` header with the `hwk` scheme is bound to the request signature, ensuring the issuer knows which public key to include in the EVT's `cnf` claim.

## Signature-Key hwk Scheme

The `hwk` (Header Web Key) scheme provides:

1. **Self-Contained Key Distribution**: The public key is transmitted inline, eliminating the need for a separate key lookup or registration process.

2. **Pseudonymity**: The browser does not need to identify itself - the key serves as a pseudonymous identifier for the request.

3. **Ephemeral Keys**: The browser generates fresh key pairs for each verification flow, limiting the correlation potential across different verification attempts.

## Email Existence Probing

Any software—not just browsers—can send requests to an issuer's issuance endpoint. An attacker could attempt to use this to probe for valid email addresses:

1. **Build email lists**: Probe many addresses to identify valid ones for spam targeting.
2. **Account enumeration**: Determine which email addresses have accounts at specific issuers.

### Uniform Error Responses

To prevent probing, issuers MUST NOT return different error responses based on whether an email address exists. The `authentication_required` error should be returned uniformly whether:

- The email address does not exist at this issuer
- The email address exists but the user is not authenticated
- The email address exists but the authenticated user does not control it

This ensures attackers cannot distinguish between "email exists" and "email does not exist" based on error responses.

### Timing Attack Mitigations

Response timing can also reveal whether an email address exists. If the issuer performs a database lookup only when the email exists, or takes different code paths based on email existence, an attacker can measure response times to infer information.

Issuers SHOULD mitigate timing attacks using techniques such as:

- **Uniform code paths**: Execute the same operations (database lookups, cryptographic operations) regardless of whether the email exists, avoiding early returns that skip processing steps.
- **Response delay normalization**: Add delays to normalize response times across all error conditions to a consistent baseline.

### Additional Mitigations

- **User interaction required**: The browser API requires user gesture and consent before initiating verification, preventing automated probing from browsers.
- **Rate limiting**: Issuers SHOULD rate-limit requests per IP address to slow down probing attempts from any client.
- **Sec-Fetch-Dest verification**: The required `Sec-Fetch-Dest: email-verification` header provides a signal that the request originates from a browser, though this can be spoofed by non-browser clients.
- **Same information as email OTP**: An attacker can already determine email existence by sending verification emails and checking for bounces. EVP does not create new information disclosure beyond what is already possible.

Issuers SHOULD implement appropriate rate limiting and abuse detection.

# Design Rationale

## Why Not Solve Email Like SMS OTP?

The WebOTP API and `autocomplete="one-time-code"` standards dramatically reduced friction for SMS verification. A natural question is why email verification cannot use the same approach. Several fundamental differences make this impractical:

**SMS is a mobile OS feature; email is application-layer**

SMS is integrated into mobile operating systems. The OS receives incoming messages and can parse them before any application sees them. This privileged position enables the OS to recognize origin-bound OTP formats and offer autofill directly to the browser.

Email operates at the application layer. There is no OS-level email subsystem that intercepts incoming messages. Email clients are ordinary applications—whether native apps, desktop programs, or web applications—with no special ability to coordinate with browsers for autofill.

**SMS verification is mobile; email verification spans platforms**

SMS OTP autofill works on mobile devices where the OS controls the messaging stack. Email verification happens on desktop computers, laptops, tablets, and phones. Any solution for email must work across all these platforms, not just mobile.

**SMS senders are aggregators; email senders are RPs**

SMS verification messages are typically sent through aggregator services (Twilio, AWS SNS, etc.) that send on behalf of many relying parties. The "sender" of the SMS is often a short code or phone number shared across multiple services. This means the phone number or sender ID carries little identifying information about which RP sent the message.

Email verification messages come directly from the RP's domain. The sender address, domain, and email headers identify the RP. This architectural difference means that email verification inherently reveals more about the RP to the email provider than SMS verification reveals to the carrier.

## Why the Three-Party Model?

A simpler design would have the issuer create a token directly for the RP, with the RP as the audience. This is how social login works: the identity provider knows which application the user is logging into.

EVP uses a three-party model where the browser intermediates between the issuer and the RP. The issuer creates an EVT bound to the browser's ephemeral public key, and the browser creates a separate KB-JWT that binds the EVT to the RP. The issuer never learns the RP's identity.

This design choice is driven by privacy: for users with domain-based email accounts (personal domains, work accounts), the email provider should not learn which applications the user accesses. The architectural complexity of the three-party model is justified by this privacy benefit.

## Why SD-JWT?

The EVT uses the SD-JWT structure (specifically, the key binding capability from SD-JWT+KB) rather than a plain JWT. This choice provides:

1. **Key Binding**: The `~` separator and KB-JWT mechanism provide a standard way to bind a token to a holder's key, enabling the three-party model where issuance and presentation are separate operations.

2. **Library Support**: SD-JWT libraries already exist and can parse EVTs, reducing implementation burden for RPs.

3. **Extensibility**: While EVP does not currently use selective disclosure, the SD-JWT structure allows future extensions without changing the token format.

## Why DNS Delegation?

The mail domain delegates email verification to an issuer via a DNS TXT record rather than a `.well-known` file. This choice aligns with how email infrastructure already works:

1. **Email domains often lack web hosting**: Many users have personal domains used only for email. Requiring a web server to host a `.well-known` file would create a barrier to adoption.

2. **Apex domain challenges**: Email domains are typically apex domains (e.g., `example.com`), which do not support CNAME records. Hosting a web site on an apex domain requires additional infrastructure.

3. **Familiar tooling**: Domain owners already manage DNS records for email (MX, SPF, DKIM, DMARC). Adding another TXT record fits existing workflows.

## Why JWKS Over DKIM Keys?

The issuer publishes signing keys via a JWKS endpoint rather than reusing DKIM keys. While DKIM keys are already associated with email domains, JWKS provides practical advantages:

1. **Key rotation**: DKIM keys are rarely rotated in practice. JWKS rotation is common in OIDC deployments and follows established patterns.

2. **Algorithm flexibility**: JWKS supports multiple key types and algorithms. DKIM key distribution was designed for a specific use case.

3. **Operational familiarity**: Developers implementing EVP are likely familiar with JWKS from OAuth/OIDC work.

## Why HTTP Message Signatures Rather Than Request JWT?

The original design used a JWT signed by the browser to carry the email address and browser's public key. The HTTP Message Signatures approach was chosen because:

1. **Standards-Based**: [@!RFC9421] is a published standard for signing HTTP messages, providing better interoperability
2. **Cookie Binding**: HTTP Message Signatures can directly sign the `cookie` header, providing stronger binding between authentication cookies and the request
3. **Content Integrity**: The `content-digest` component provides built-in content integrity without needing to duplicate the email in a JWT
4. **Flexibility**: The signature can cover any HTTP components, making it easier to add additional protections in the future
5. **Simpler Key Distribution**: The Signature-Key header provides a standardized way to distribute keys inline with the request

{backmatter}

# Acknowledgments

The authors would like to thank reviewers for their feedback on this specification.
