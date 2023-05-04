import React, { useEffect, useRef } from 'react';
import { generatePrivateKey, importPrivateKey } from './crypto/KeyHolder';
import {
  eciesLegacyDecrypt,
  eciesLegacyEncrypt,
} from './crypto/operations/eciesLegacy';
import {
  aesGCMIgnoreTagDecrypt,
  aesGCMIgnoreTagEncrypt,
} from './crypto/operations/aes';
import { ecdsaSign, ecdsaVerify } from './crypto/operations/ecdsa';
import { hmacSign } from './crypto/operations/hmac';
import { useState } from 'react';
import { ScrollView, Text, View } from 'react-native';
import { Button } from '../Button';
import {
  defaultImplementation,
  EcdhComputeSecretFunction,
  getECDHComputeSecretFunction,
  setEcdhComputeSecretImplementation,
} from './crypto/implementations/ecdhComputeSecret';

const dummyPrivatePart = `"privatePart":{"commonFriends":[MEEe3tRp7bx+hRA7osU/x+hhMVy6PiAfBR3Gu2r+MEEe3tRp7bx+hRA7osU/x+hhMVy6PiAfBR3Gu2r+MEEe3tRp7bx+hRA7osU/x+hhMVy6PiAfBR3Gu2r+MEEe3tRp7bx+hRA7osU/x+hhMVy6PiAfBR3Gu2r+MEEe3tRp7bx+hRA7osU/x+hhMVy6PiAfBR3Gu2r+MEEe3tRp7bx+hRA7osU/x+hhMVy6PiAfBR3Gu2r+MEEe3tRp7bx+hRA7osU/x+hhMVy6PiAfBR3Gu2r+MEEe3tRp7bx+hRA7osU/x+hhMVy6PiAfBR3Gu2r+],"friendLevel":["NOT_SPECIFIED"],"symmetricKey":"MEEe3tRp7bx+hRA7osU/x+hhMVy6PiAfBR3Gu2r+RG0="},`;
const dummyPublicPart = `"publicPart":{"offerPublicKey":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUFvRFFnQUVUTlhndG9GMVRBNVVrVWZ4YWFBbHp4cDBRSFlwZS8yVApFSk1nQXR0d0tabnZBZFBUVUNXdCtweGhpWGUzNDNlbjNndHI5OHZoS1pZSGc4VGRQT3JHMEE9PQotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0K","location":[{"longitude":"14.4212535000000006135678631835617125034332275390625","latitude":"50.0874653999999992493030731566250324249267578125","city":"Prague"}],"offerDescription":"test","amountBottomLimit":0,"amountTopLimit":250000,"feeState":"WITHOUT_FEE","feeAmount":1,"locationState":"ONLINE","paymentMethod":["CASH"],"btcNetwork":["LIGHTING"],"currency":"CZK","offerType":"SELL","activePriceState":"NONE","activePriceValue":0,"activePriceCurrency":"CZK","active":true,"groupUuids":[]},`;
const dummySymetricKey = 'MEEe3tRp7bx+hRA7osU/x+hhMVy6PiAfBR3Gu2r+RG0=';
const dummyPhoneNumber = '+420733333333';

const numberFormatIntl = new Intl.NumberFormat('cs', {});
function msToString(ms: number): string {
  return `${numberFormatIntl.format(ms / 1000)} seconds`;
}

const NUMBER_OF_ITERATION_TO_TEST = 100;

async function* runBenchmark() {
  const keypair1 = generatePrivateKey();

  const encryptedPrivateParts = [];
  // ECIES

  const startedAt = Date.now();
  let nowMs = Date.now();
  yield `ECIES encrypting dummy private parts ${NUMBER_OF_ITERATION_TO_TEST} times`;
  for (let i = 0; i < NUMBER_OF_ITERATION_TO_TEST; i++) {
    const one = await eciesLegacyEncrypt({
      publicKey: keypair1.publicKeyPemBase64,
      data: dummyPrivatePart,
    });
    encryptedPrivateParts.push(one);
  }
  yield `Took ${msToString(Date.now() - nowMs)}`;
  const eciesEncryptDuration = Date.now() - nowMs;

  nowMs = Date.now();
  yield `ECIES decrypting dummy private parts ${NUMBER_OF_ITERATION_TO_TEST} times`;
  for (let i = 0; i < encryptedPrivateParts.length; i++) {
    await eciesLegacyDecrypt({
      privateKey: keypair1.privateKeyPemBase64,
      data: encryptedPrivateParts[i],
    });
  }
  yield `Took ${msToString(Date.now() - nowMs)}`;
  const eciesDecryptDuration = Date.now() - nowMs;

  nowMs = Date.now();
  const encryptedPublicParts = [];
  yield `AES encrypting dummy public parts ${NUMBER_OF_ITERATION_TO_TEST} times`;
  for (let i = 0; i < NUMBER_OF_ITERATION_TO_TEST; i++) {
    const data = aesGCMIgnoreTagEncrypt({
      data: dummyPublicPart,
      password: dummySymetricKey,
    });
    encryptedPublicParts.push(data);
  }
  yield `Took ${msToString(Date.now() - nowMs)}`;
  const aesEncryptDuration = Date.now() - nowMs;

  nowMs = Date.now();
  yield `AES decrypting dummy public parts ${NUMBER_OF_ITERATION_TO_TEST} times`;
  for (let i = 0; i < encryptedPublicParts.length; i++) {
    aesGCMIgnoreTagDecrypt({
      data: encryptedPublicParts[i],
      password: dummySymetricKey,
    });
  }
  yield `Took ${msToString(Date.now() - nowMs)}`;
  const aesDecryptDuration = Date.now() - nowMs;

  nowMs = Date.now();
  yield `ECDSA signing dummy phone number ${NUMBER_OF_ITERATION_TO_TEST} times`;
  for (let i = 0; i < NUMBER_OF_ITERATION_TO_TEST; i++) {
    ecdsaSign({
      privateKey: keypair1,
      challenge: dummySymetricKey,
    });
  }
  yield `Took ${msToString(Date.now() - nowMs)}`;
  const ecdsaSignatureDuration = Date.now() - nowMs;

  yield `HMAC signing dummy phone number ${NUMBER_OF_ITERATION_TO_TEST} times`;
  nowMs = Date.now();
  for (let i = 0; i < NUMBER_OF_ITERATION_TO_TEST; i++) {
    hmacSign({ data: dummyPhoneNumber, password: 'VexlVexl' });
  }
  yield `Took ${msToString(Date.now() - nowMs)}`;

  yield `Done in ${msToString(Date.now() - startedAt)}!`;
  const hmacDuration = Date.now() - nowMs;

  return {
    eciesEncryptDuration: msToString(eciesEncryptDuration),
    eciesDecryptDuration: msToString(eciesDecryptDuration),
    aesEncryptDuration: msToString(aesEncryptDuration),
    aesDecryptDuration: msToString(aesDecryptDuration),
    ecdsaSignatureDuration: msToString(ecdsaSignatureDuration),
    hmacDuration: msToString(hmacDuration),
  };
}

async function* startTests() {
  yield `Tests running`;

  yield `generating keypair`;
  const keypair1 = generatePrivateKey();

  yield `Testing Ecies`;
  const encrypted = await eciesLegacyEncrypt({
    publicKey: keypair1.publicKeyPemBase64,
    data: dummyPrivatePart,
  });
  const decrypted = await eciesLegacyDecrypt({
    privateKey: keypair1.privateKeyPemBase64,
    data: encrypted,
  });

  if (decrypted !== dummyPrivatePart) {
    yield `🚨 ECIES failed`;
  } else {
    yield `✅ ECIES OK`;
  }

  yield `Testing ECIES decryption with another cypher`;
  const cipher =
    '172Ar+8ScAMaOn02z6bkOcUtorl6DtxHpXbWsBETrqYvhejx4090WFpLkuhoyzTypfq0woiNm/crqBU9Gw54w2h3qD1BhFwI0TwqUg9grhRd2X/mos4R6V1FtL9O7KAkg4cT72NX3KzWJ74mEjYDPMq8UUtL8ea5bHJgeS88SKivNEY=44AoDQx3spJHWDcfV5iIwT+aU7AAgNMcGCDg9iiS+NNQbU=40AA2NBtH0bhf2o39IF45r5NufcYF8G5m16LqZPSso=';
  const privateKeyForCipher = importPrivateKey({
    privateKeyPemBase64:
      'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1IZ0NBUUF3RUFZSEtvWkl6ajBDQVFZRks0RUVBQ0VFWVRCZkFnRUJCQnhJWTl5Q3prMU4vWXU3UFZlbVJWc1QKTStCYjFMODRWbDNUZ2QvMm9Ud0RPZ0FFWUFxNWc5RGxBZ1VSWHUvc3JKQnByRWNnYlp3cDBJL2xudjgvR2NQNApGeU92YkorQXZ1RzZjL1pXR0lldUVSVXpKVlZIZzVyVjRRND0KLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=',
  });
  const decryptedCypher = await eciesLegacyDecrypt({
    privateKey: privateKeyForCipher.privateKeyPemBase64,
    data: cipher,
  });
  if (decryptedCypher !== 'Test message') {
    yield `🚨 ECIES did not decipher as expected.`;
  } else {
    yield `✅ ECIES decipher OK`;
  }

  yield `Testing AES`;
  const encrypted2 = aesGCMIgnoreTagEncrypt({
    data: dummyPublicPart,
    password: dummySymetricKey,
  });
  const decrypted2 = aesGCMIgnoreTagDecrypt({
    data: encrypted2,
    password: dummySymetricKey,
  });
  if (decrypted2 !== dummyPublicPart) {
    yield `🚨  AES failed`;
  } else {
    yield `✅ AES OK`;
  }

  yield `Testing ECDSA`;
  const signature = ecdsaSign({
    privateKey: keypair1,
    challenge: dummySymetricKey,
  });
  if (
    !ecdsaVerify({
      challenge: dummySymetricKey,
      signature,
      pubKey: keypair1.publicKeyPemBase64,
    })
  ) {
    yield `🚨  ECDSA failed`;
  } else {
    yield `✅ ECDSA OK`;
  }
}

function createDummyImplementation(
  msDelay: number
): typeof defaultImplementation {
  return async () => {
    return await new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          publicKey: Buffer.from('foo'),
          secret: Buffer.from('bar'),
        });
      }, msDelay);
    });
  };
}

const dummy10msImplementation = createDummyImplementation(10);
const dummy0msImplementation = createDummyImplementation(0);

// setEcdhComputeSecretImplementation(createDummyImplementation(2))

export default function VexlTests(): JSX.Element {
  const [text, setText] = useState('Not started yet');
  const shouldRunRef = useRef(false);

  // For UI only
  const [
    currentImplementationReference,
    setTrackingRefrerenceForCurrentImplementation,
  ] = useState<{ impl: EcdhComputeSecretFunction }>({
    impl: getECDHComputeSecretFunction(),
  });

  function addText(text: string): void {
    setText((prev) => `${prev}\n${text}`);
  }

  async function printGenerator(
    generator: AsyncGenerator<string, any, unknown>
  ) {
    setText('');
    shouldRunRef.current = true;
    let curr = await generator.next();

    while (!curr.done && shouldRunRef.current) {
      addText(curr.value);
      curr = await generator.next();
    }

    if (!shouldRunRef.current) {
      addText('cancelled');
    }
  }

  useEffect(() => {
    return () => {
      setEcdhComputeSecretImplementation(defaultImplementation);
    };
  }, []);

  return (
    <ScrollView>
      <View>
        <Text>
          For each crypto operation, we run {NUMBER_OF_ITERATION_TO_TEST}{' '}
          iterations and measure the time
        </Text>
        <Text>
          {currentImplementationReference.impl === defaultImplementation &&
            'Using implementation provided by react-native-crypto'}
          {currentImplementationReference.impl === dummy10msImplementation &&
            'Using dummy 10ms implementation'}
          {currentImplementationReference.impl === dummy0msImplementation &&
            'Using dummy instant implementation'}
        </Text>
        <Text>{text}</Text>
        <Button
          onPress={async () => {
            setText('');
            const generator = runBenchmark();
            await printGenerator(generator);
          }}
          title={'Run benchmark'}
        />
        <Button
          onPress={async () => {
            setText('');
            const generator = startTests();
            await printGenerator(generator);
          }}
          title={'Run tests'}
        />
        <Button
          onPress={() => {
            shouldRunRef.current = false;
          }}
          title="Stop"
        />
        <Button
          onPress={() => {
            setEcdhComputeSecretImplementation(defaultImplementation);
            setTrackingRefrerenceForCurrentImplementation({
              impl: defaultImplementation,
            });
          }}
          title="set real implementation"
        />
        <Button
          onPress={() => {
            setEcdhComputeSecretImplementation(dummy10msImplementation);
            setTrackingRefrerenceForCurrentImplementation({
              impl: dummy10msImplementation,
            });
          }}
          title="set 10ms implementation"
        />
        <Button
          onPress={() => {
            setEcdhComputeSecretImplementation(dummy0msImplementation);
            setTrackingRefrerenceForCurrentImplementation({
              impl: dummy0msImplementation,
            });
          }}
          title="set instant implementation"
        />
      </View>
    </ScrollView>
  );
}
