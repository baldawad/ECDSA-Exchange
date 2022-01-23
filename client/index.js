import "./index.scss";
const EC = require('elliptic').ec;
const SHA256 = require('crypto-js/sha256');

const ec = new EC('secp256k1');

const server = "http://localhost:3042";

document.getElementById("exchange-address").addEventListener('input', ({ target: {value} }) => {
  if(value === "") {
    document.getElementById("balance").innerHTML = 0;
    return;
  }

  fetch(`${server}/balance/${value}`).then((response) => {
    return response.json();
  }).then(({ balance }) => {
    document.getElementById("balance").innerHTML = balance;
  });
});

document.getElementById("transfer-amount").addEventListener('click', () => {
  const privateKey = document.getElementById("private-key").value;
  const amount = document.getElementById("send-amount").value;
  const recipient = document.getElementById("recipient").value;
  const senderAddress = document.getElementById("exchange-address").value;

  /* We will send 3 componenents to server to verify the transaction
  a. Original transaction which will have recipient and amount
  b. DER of signature signed by private key of owner on hash of (a)
  c. Public key of signed primary key to validate
  The server will use (b) and using (c) will verify if valid (b) was provided 
  */
  
  // Define the transaction/message to be digitally signed by private key
  const transaction = {"recipient": recipient,"amount":amount}

  const key = ec.keyFromPrivate(privateKey);
  const msgHash = SHA256(JSON.stringify(transaction));
  const signature = key.sign(msgHash.toString());

  if (senderAddress.toString() !== key.getPublic().encode('hex').toString() ||
      recipient.toString() === senderAddress.toString())
    document.getElementById("transfer-amount").disabled = true;
  else
    document.getElementById("transfer-amount").disabled = false;

  const body = JSON.stringify({
    "signature":signature.toDER(), "transaction":transaction,"publicKey": key.getPublic().encode('hex')})

  const request = new Request(`${server}/send`, { method: 'POST', body });

  fetch(request, { headers: { 'Content-Type': 'application/json' }}).then(response => {
    return response.json();
  }).then(({ balance }) => {
    document.getElementById("balance").innerHTML = balance;
  });
});
