// shamelessly copied (and modified) from https://github.com/auth0/node-saml

var crypto = require('crypto');
var zlib = require('zlib');
var fs = require('fs');
var path = require('path');
var Buffer = require('buffer').Buffer;
var Parser = require('xmldom').DOMParser;
var SignedXml = require('xml-crypto').SignedXml;
var samlp = fs.readFileSync(path.join(__dirname, 'samlp.tpl'), 'utf8');

function pemToCert(pem) {
  var cert = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(pem.toString());
  if (cert.length > 0) {
    return cert[1].replace(/[\n|\r\n]/g, '');
  }

  return null;
}

function removeWhitespace(xml) {
  return xml.replace(/\r\n/g, '').replace(/\n/g,'').replace(/>(\s*)</g, '><').trim();
}

var ASSERTION_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
var SAMLP_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';

var algorithms = {
  signature: {
    'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'rsa-sha1':  'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  },
  digest: {
    'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1'
  }
};

exports.parseRequest = function(options, request, callback) {
  options.issuer = options.issuer || 'http://capriza.com/samling';
  request = decodeURIComponent(request);
  var buffer = new Buffer(request, 'base64');
  zlib.inflateRaw(buffer, function(err, result) {
    var info = {};
    try {
      if (!err) {
        buffer = result;
      }
      var doc = new Parser().parseFromString(buffer.toString());
      var rootElement = doc.documentElement;
      if (rootElement.localName == 'AuthnRequest') {
        info.login = {};
        info.login.callbackUrl = rootElement.getAttribute('AssertionConsumerServiceURL');
        info.login.destination = rootElement.getAttribute('Destination');
        var nameIDPolicy = rootElement.getElementsByTagNameNS(SAMLP_NS, 'NameIDPolicy')[0];
        if (nameIDPolicy) {
          info.login.nameIdentifierFormat = nameIDPolicy.getAttribute('Format');
        }
        var requestedAuthnContext = rootElement.getElementsByTagNameNS(SAMLP_NS, 'RequestedAuthnContext')[0];
        if (requestedAuthnContext) {
          var authnContextClassRef = requestedAuthnContext.getElementsByTagNameNS(ASSERTION_NS, 'AuthnContextClassRef')[0];
          if (authnContextClassRef) {
            info.login.authnContextClassRef = authnContextClassRef.textContent;
          }
        }
      } else if (rootElement.localName == 'LogoutRequest') {
        info.logout = {};
        info.logout.callbackUrl = options.callbackUrl;
        info.logout.response =
            '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_' + crypto.randomBytes(21).toString('hex') +
            '" Version="2.0" IssueInstant="' + new Date().toISOString() + '" Destination="' + info.logout.callbackUrl + '">' +
            '<saml:Issuer>' + options.issuer + '</saml:Issuer>' +
            '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
            '</samlp:LogoutResponse>';
      }
    } catch(e) {
    }
    callback(info);
  });
};

exports.createAssertion = function(options) {
  if (!options.key)
    throw new Error('Expecting a private key in pem format');

  if (!options.cert)
    throw new Error('Expecting a public key cert in pem format');

  options.signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha256';
  options.digestAlgorithm = options.digestAlgorithm || 'sha256';

  var doc = new Parser().parseFromString(samlp.toString());

  doc.documentElement.setAttribute('ID', '_' + (options.uid || crypto.randomBytes(21).toString('hex')));
  if (options.issuer) {
    var issuer = doc.documentElement.getElementsByTagName('saml:Issuer');
    issuer[0].textContent = options.issuer;
  }

  var now = new Date().toISOString();
  doc.documentElement.setAttribute('IssueInstant', now);
  var conditions = doc.documentElement.getElementsByTagName('saml:Conditions');
  var confirmationData = doc.documentElement.getElementsByTagName('saml:SubjectConfirmationData');

  if (options.lifetimeInSeconds) {
    var expires = new Date(Date.now() + options.lifetimeInSeconds*1000).toISOString();
    conditions[0].setAttribute('NotBefore', now);
    conditions[0].setAttribute('NotOnOrAfter', expires);
    confirmationData[0].setAttribute('NotOnOrAfter', expires);
  }

  if (options.audiences) {
    var audienceRestrictionsElement = doc.createElementNS(ASSERTION_NS, 'saml:AudienceRestriction');
    var audiences = options.audiences instanceof Array ? options.audiences : [options.audiences];
    audiences.forEach(function (audience) {
      var element = doc.createElementNS(ASSERTION_NS, 'saml:Audience');
      element.textContent = audience;
      audienceRestrictionsElement.appendChild(element);
    });
    conditions.appendChild(audienceRestrictionsElement);
  }

  if (options.recipient)
    confirmationData[0].setAttribute('Recipient', options.recipient);

  if (options.inResponseTo)
    confirmationData[0].setAttribute('InResponseTo', options.inResponseTo);

  if (options.attributes) {
    var statement = doc.createElementNS(ASSERTION_NS, 'saml:AttributeStatement');
    statement.setAttribute('xmlns:xs', 'http://www.w3.org/2001/XMLSchema');
    statement.setAttribute('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
    Object.keys(options.attributes).forEach(function(prop) {
      if(typeof options.attributes[prop] === 'undefined') return;
      var attributeElement = doc.createElementNS(ASSERTION_NS, 'saml:Attribute');
      attributeElement.setAttribute('Name', prop);
      var values = options.attributes[prop] instanceof Array ? options.attributes[prop] : [options.attributes[prop]];
      values.forEach(function (value) {
        var valueElement = doc.createElementNS(ASSERTION_NS, 'saml:AttributeValue');
        valueElement.setAttribute('xsi:type', 'xs:anyType');
        valueElement.textContent = value;
        attributeElement.appendChild(valueElement);
      });

      if (values && values.length > 0) {
        // saml:Attribute must have at least one saml:AttributeValue
        statement.appendChild(attributeElement);
      }
    });
    doc.appendChild(statement);
  }

  doc.getElementsByTagName('saml:AuthnStatement')[0].setAttribute('AuthnInstant', now);

  if (options.sessionIndex) {
    doc.getElementsByTagName('saml:AuthnStatement')[0].setAttribute('SessionIndex', options.sessionIndex);
  }

  var nameID = doc.documentElement.getElementsByTagNameNS(ASSERTION_NS, 'NameID')[0];

  if (options.nameIdentifier) {
    nameID.textContent = options.nameIdentifier;
  }

  if (options.nameIdentifierFormat) {
    nameID.setAttribute('Format', options.nameIdentifierFormat);
  }

  if( options.authnContextClassRef ) {
    var authnCtxClassRef = doc.getElementsByTagName('saml:AuthnContextClassRef')[0];
    authnCtxClassRef.textContent = options.authnContextClassRef;
  }

  var token = removeWhitespace(doc.toString());
  var signed;

  var cert = pemToCert(options.cert);

  var sig = new SignedXml(null, { signatureAlgorithm: algorithms.signature[options.signatureAlgorithm], idAttribute: 'ID' });
  sig.signingKey = options.key;
  sig.addReference("//*[local-name(.)='Assertion']",
      ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
      algorithms.digest[options.digestAlgorithm]);
  sig.keyInfoProvider = {
    getKeyInfo: function (key, prefix) {
      return '<'+prefix+':X509Data><'+prefix+':X509Certificate>' + cert + '</'+prefix+':X509Certificate></'+prefix+':X509Data>';
    }
  };
  sig.computeSignature(token, {prefix: 'ds', location: {action: 'after', reference : "//*[local-name(.)='Issuer']"}});
  signed = sig.getSignedXml();

  return signed;
};

exports.createResponse = function(options) {
  var response = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"';
  response += ' ID="_' + crypto.randomBytes(21).toString('hex') + '"';
  response += ' IssueInstant="' + options.instant + '"';
  if (options.inResponseTo) {
    response += ' InResponseTo="' + options.inResponseTo + '"';
  }
  if (options.callbackUrl) {
    response += ' Destination="' + options.callbackUrl + '"';
  }
  response += '><saml:Issuer>' + options.issuer + '</saml:Issuer>';
  response += '<samlp:Status><samlp:StatusCode Value="' + options.samlStatusCode + '"/>';
  if (options.samlStatusMessage) {
    response += '<samlp:StatusMessage>' + options.samlStatusMessage + '</samlp:StatusMessage>';
  }
  response += '</samlp:Status>';
  response += options.assertion;
  response += '</samlp:Response>';

  return response;
};
