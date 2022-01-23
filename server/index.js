const express = require('express');
const app = express();
const cors = require('cors');
const SHA256 = require('crypto-js/sha256') // Including reference to SHA256
const port = 3042;
const EC = require('elliptic').ec; // Including reference to elliptic module

// localhost can have cross origin errors
// depending on the browser you use!
app.use(cors());
app.use(express.json());

const ec = new EC('secp256k1'); // constructor for elliptic initializes to secp256k1 ECDSA algorithm

// Generate 3 keys-pairs
const key1 = ec.genKeyPair(); // generate public/private key pair1
const key2 = ec.genKeyPair(); // generate public/private key pair2
const key3 = ec.genKeyPair(); // generate public/private key pair3

//Add public private key-pair object for above 3 keys into an array
/*const keypairs = [{public:SHA256(key1.getPublic().encode('hex')).toString().slice(-40),private:key1.getPrivate().toString(16)},
                  {public:SHA256(key2.getPublic().encode('hex')).toString().slice(-40),private:key2.getPrivate().toString(16)},
                  {public:SHA256(key3.getPublic().encode('hex')).toString().slice(-40),private:key3.getPrivate().toString(16)}
                 ]*/

console.log(key1.getPublic().encode('hex'))
console.log(key1.getPublic().encode('hex').toString())

const keypairs = [{public:key1.getPublic().encode('hex'),private:key1.getPrivate().toString(16)},
                  {public:key2.getPublic().encode('hex'),private:key2.getPrivate().toString(16)},
                  {public:key3.getPublic().encode('hex'),private:key3.getPrivate().toString(16)}
                 ]

// Assign balances to their respective public keys
const balances = {
  [keypairs[0].public]: 100,
  [keypairs[1].public]: 50,
  [keypairs[2].public]: 75,
}

console.log("Available Accounts")
keypairs.forEach((x,i)=>{
  console.log(`(${i}) ${x.public} (${balances[x.public]})`)
})

console.log("           ")
console.log("Private Keys")
keypairs.forEach((x,i)=>{
  console.log(`(${i}) ${x.private}`)
})

app.get('/balance/:address', (req, res) => {
  const {address} = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post('/send', (req, res) => {
  const {signature, transaction, publicKey} = req.body;
  const key = ec.keyFromPublic(publicKey, 'hex');
  
  console.log(key.verify(SHA256(JSON.stringify(transaction)).toString(),signature));

  if (key.verify(SHA256(JSON.stringify(transaction)).toString(),signature) && balances.hasOwnProperty(transaction.recipient)){
    console.log("sender public:"+publicKey)
    console.log("recipient public:"+transaction.recipient)
    console.log("sender balance: "+balances[publicKey]);
    console.log("recipient balance: "+balances[transaction.recipient]);
    balances[publicKey] -= transaction.amount;
    balances[transaction.recipient] = (balances[transaction.recipient] || 0) + +transaction.amount;
    res.send({ balance: balances[publicKey] });
  }
  else{
    res.statusMessage = "Private key is incorrect or Recipient key is incorrect";
    res.status(400).end("Private key is incorrect or Recipient key is incorrect")
  } 
  

});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});
