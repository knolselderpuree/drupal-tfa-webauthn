"use strict";
document.addEventListener("DOMContentLoaded", init);

function init() {
  const challenge = document.getElementById("challenge").value;
  const username = document.getElementById("username").value;
  const email = document.getElementById("email").value;
  const options = {
    rp: {
      name: "atlas.groupflights.com",
      id: window.location.hostname,
    },
    user: {
      id: Uint8Array.from("some value from your application", c => c.charCodeAt(0)),
      name: username,
      displayName: email,
    },
    challenge: Uint8Array.from(challenge, c => c.charCodeAt(0)),
    pubKeyCredParams: [
      {type: "public-key", "alg": -7},
      {type: "public-key", "alg": -257},
    ],
    timeout: 600000,
    authenticatorSelection: {
      authenticatorAttachment: "cross-platform",
      userVerification: "preferred",
    },
    attestation: "direct"
  };

  navigator.credentials.create({
    publicKey: options
  }).then((credential) => {
    const dataToSend = {
      rawId: new Uint8Array(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: new Uint8Array(credential.response.attestationObject),
        clientDataJSON: new Uint8Array(credential.response.clientDataJSON),
      },
    };
    document.getElementById("hostname").value = window.location.hostname;
    document.getElementById("response").value = JSON.stringify(dataToSend);
  });
}
