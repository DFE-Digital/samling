![samling logo](/public/samling.png)

Serverless (as in "client side only") SAML IDP for testing SAML integrations.

## Live SAMLING

Visit http://capriza.github.io/samling/samling.html to see it in action.

## What is SAMLING

SAMLING is a Serverless (as-in client side only) SAML IdP for the purpose of testing SAML integrations.

It provides complete control over the SAML response properties that will be sent back to the Service Provider, including simulating errors and the session cookie
duration that tracks the logged-in user.
If there is a <strong>SAMLRequest</strong> query parameter present, SAMLING will auto populate some of the SAML Response Properties.

Generating a SAML Response requires the use of a private key and certificate for signing the SAML Assertion.
SAMLING enables to generate a random private/public key and to save them in the local storage so they are used in subsequent SAML responses.</p>

## How to Use

1. Go to the **SAML Response Properties** section.
2. Fill in the required properties fields. Required fields are marked with an asterisks (*).
3. Click on **Create Response**. You will be be taken the **SAML Response** section.
4. Review the SAML Response then click on **Post Response**.

## License

The MIT License (MIT)

Copyright (c) 2016 Capriza Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

