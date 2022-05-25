let count = 0;
(function ($, Drupal) {
  Drupal.behaviors.webauthn = {
    attach: function (context, settings) {
      if (document.getElementById('sign_request').value && count === 0) {
        count++;
        const fromBase64Web = s => atob(s.replace(/\-/g, '+').replace(/_/g, '/'));
        const signRequest = JSON.parse(document.getElementById("sign_request").value);
        const options = {
          challenge: Uint8Array.from(signRequest.challenge, c => c.charCodeAt(0)),
          allowCredentials: signRequest.keyHandles.map(kh => ({
            id: Uint8Array.from(fromBase64Web(kh), c => c.charCodeAt(0)),
            type: "public-key",
            transport: ["usb", "ble", "nfc"],
          })),
          timeout: 600000,
        };
        navigator.credentials.get({
          publicKey: options
        }).then((assertion) => {
          const dataToSend = {
            rawId: new Uint8Array(assertion.rawId),
            type: assertion.type,
            response: {
              authenticatorData: new Uint8Array(assertion.response.authenticatorData),
              clientDataJSON: new Uint8Array(assertion.response.clientDataJSON),
              signature: new Uint8Array(assertion.response.signature)
            },
          };
          document.getElementById("response").value = JSON.stringify(dataToSend);
          document.getElementById("step").value = count;
        })
      }
    },
    detach: function (context, settings) {
      count = 0;
      document.getElementById("response").value = "";
      document.getElementById("sign_request").value = "";
      document.getElementById("step").value = count;
    }
  };
})(jQuery, Drupal);
