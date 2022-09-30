const ION = require("@decentralized-identity/ion-tools");
const fs = require("fs").promises;
const JWS = require("@transmute/jose-ld").JWS;

const create = async () => {
  // Create private/public key pair
  const keypair = await ION.generateKeyPair("secp256k1");
  console.log("Created private/public key pair");
  console.log("keypair:", keypair);
  // Write private and public key to files
  await fs.writeFile("keypair.json", JSON.stringify(keypair));
  console.log("Wrote private key to keypair.json");
  // Create a DID
  const did = new ION.DID({
    content: {
      // Register the public key for authentication
      publicKeys: [
        {
          id: "auth-key",
          type: "EcdsaSecp256k1VerificationKey2019",
          publicKeyJwk: keypair.publicKeyJwk,
          purposes: ["authentication"],
        },
      ],
      // Register an IdentityHub as a service
      services: [
        {
          id: "IdentityHub",
          type: "IdentityHub",
          serviceEndpoint: {
            "@context": "schema.identity.foundation/hub",
            "@type": "UserServiceEndpoint",
            instance: ["did:test:hub.id"],
          },
        },
      ],
    },
  });
  const didUri = await did.getURI("short");
  console.log("Generated DID:", didUri);
  const anchorRequestBody = await did.generateRequest();
  const anchorRequest = new ION.AnchorRequest(anchorRequestBody);
  const anchorResponse = await anchorRequest.submit();
  console.log(JSON.stringify(anchorResponse));
};

const search = async (id) => {
  const resolvedDid = await ION.resolve(id);
  console.log(JSON.stringify(resolvedDid));
};

const sign = async (msg) => {
  const row = JSON.parse(await fs.readFile("keypair.json"));
  const keypair = await ION.from(row);
  const JWA_ALG = "ES256K";
  const signer = JWS.createSigner(keypair.signer("Ecdsa"), JWA_ALG);
  const verifier = JWS.createVerifier(keypair.verifier("Ecdsa"), JWA_ALG);
  const message = Uint8Array.from(Buffer.from(msg));
  const signature = await signer.sign({ data: message });
  console.log(signature);
  const verified = await verifier.verify({ signature });
  console.log(verified);
};

args = process.argv.slice(2);
console.log(args);
switch (args[0]) {
  case "create":
    create();
    break;
  case "search":
    search(args[1]);
    break;
  case "sign":
    sign(args[1]);
    break;
}