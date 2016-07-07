![samling logo](/public/samling2.png)

Serverless (as in "client side only") SAML IDP for testing SAML integrations.

## See it Live

Visit https://capriza.github.io/samling/samling.html to see it in action.

## What is SAMLING

SAMLING is a Serverless (as-in client side only) SAML IdP for the purpose of testing SAML integrations.

It provides control over the SAML response properties to send back to the Service Provider in response to a SAML request,
including simulating errors and specifying session cookie duration to track the logged-in user.

If there is a <strong>SAMLRequest</strong> query parameter present with an `AuthnRequest`,
SAMLING will auto populate some of the fields in the `SAML Response Properties` section in preparation for creating the SAML response.

If there is a <strong>SAMLRequest</strong> query parameter present with a `LogoutRequest`,
SAMLING will log out the currently logged-in user.

Generating a SAML Response requires the use of a private key and certificate for signing the SAML Assertion.
SAMLING enables to generate a random private/public key and to save them in the local storage so they are used in
subsequent SAML responses.

## Installation

```bash
git clone https://github.com/capriza/samling.git
cd samling
npm install
npm run build
```

You'll end up with a `public` directory with all the required assets for loading `samling.html`.

## How to Use

1. Open up `https://capriza.github.io/samling/samling.html`. You'll land on the **SAML Response Properties** section.
2. Fill in the required properties fields. Required fields are marked with an asterisks (*).
   * `Name Identifier` - the user name
   * `Callback URL` - where to send the SAML response
   * `Private Key` -  the private key to use for siging the SAML assertion
   * `Public Certificate` - the public certificate to embed in the SALM response
   * `New Pair` - generate a new private/public key pair
   * `Save` - save the private key and public certificate to the local storage so that they are automatically loaded on re-visits.
3. Click on **Create Response**. You will be be taken the **SAML Response** section.
4. Review the SAML response and set the session duration, then click on **Post Response**. At this point a session cookie
   is created for the logged in user.
5. You can reload the samling page and go to the **User Details** page to verify the session cookie was created.

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

