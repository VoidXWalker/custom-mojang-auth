import crypto from 'node:crypto';

const PUBLIC_KEY_PREFIX = "-----BEGIN PUBLIC KEY-----\n";
const PUBLIC_KEY_SUFFIX = "\n-----END PUBLIC KEY-----";

const yggdrasilSessionKey = crypto.createPublicKey(PUBLIC_KEY_PREFIX + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAylB4B6m5lz7jwrcFz6Fd/fnfUhcvlxsTSn5kIK/2aGG1C3kMy4VjhwlxF6BFUSnfxhNswPjh3ZitkBxEAFY25uzkJFRwHwVA9mdwjashXILtR6OqdLXXFVyUPIURLOSWqGNBtb08EN5fMnG8iFLgEJIBMxs9BvF3s3/FhuHyPKiVTZmXY0WY4ZyYqvoKR+XjaTRPPvBsDa4WI2u1zxXMeHlodT3lnCzVvyOYBLXL6CJgByuOxccJ8hnXfF9yY4F0aeL080Jz/3+EBNG8RO4ByhtBf4Ny8NQ6stWsjfeUIvH7bU/4zCYcYOq4WrInXHqS8qruDmIl7P5XXGcabuzQstPf/h2CRAUpP/PlHXcMlvewjmGU6MfDK+lifScNYwjPxRo4nKTGFZf/0aqHCh/EAsQyLKrOIYRE0lDG3bzBh8ogIMLAugsAfBb6M3mqCqKaTMAf/VAjh5FFJnjS+7bE+bZEV0qwax1CEoPPJL1fIQjOS8zj086gjpGRCtSy9+bTPTfTR/SJ+VUB5G2IeCItkNHpJX2ygojFZ9n5Fnj7R9ZnOM+L8nyIjPu3aePvtcrXlyLhH/hvOfIOjPxOlqW+O5QwSFP4OEcyLAUgDdUgyW36Z5mB285uKW/ighzZsOTevVUG2QwDItObIV6i8RCxFbN2oDHyPaO5j1tTaBNyVt8CAwEAAQ==" + PUBLIC_KEY_SUFFIX);
const SIGNATURE_ALGORITHM = "RSA-SHA256";
const SIGNATURE_ALGORITHM2 = "RSA-SHA1";
const DIGEST_ALGORITHM = "sha256";
const BASE_64 = "base64";

export function isValid(uuid, randomLong, data, date, publicKeyString, signatureBytes, payload) {
  try {
    const buf1 = Buffer.alloc(294);
    const uint16array1 = new Int8Array(
      buf1.buffer,
      buf1.byteOffset,
      buf1.length / Int8Array.BYTES_PER_ELEMENT
    );
    buf1.write(publicKeyString, BASE_64);
    if (verify(uuid, yggdrasilSessionKey, signatureBytes, date, Buffer.from(uint16array1))) {
      const publicKey = crypto.createPublicKey(PUBLIC_KEY_PREFIX + publicKeyString + PUBLIC_KEY_SUFFIX);
      const verifier = crypto.createVerify(SIGNATURE_ALGORITHM);
      verifier.update(uuid);
      verifier.update(digest(randomLong));
      verifier.update("70");
      for (let index = 0; index < payload.length; ++index) {
        verifier.update(payload[index]);
      }
      verifier.end();
      return verifier.verify(publicKey, Buffer.from(data, BASE_64)) ? toUuidString(uuid) : null;
    }
    return null;
  } catch (e) {
    return null;
  }
}


function digest(randomLong) {
  let hash = crypto.createHash(DIGEST_ALGORITHM);
  hash.update(randomLong);
  hash.update("70");
  hash.end();
  return hash.digest().toString(BASE_64);
}


function verify(uuid, publicKey, signatureBytes, date, key2) {
  const verify = crypto.createVerify(SIGNATURE_ALGORITHM2);
  verify.update(toSerializedString(uuid, date, key2));
  verify.end();
  return verify.verify(publicKey, Buffer.from(signatureBytes, BASE_64)) && !date < Date.now();
}


function toSerializedString(uuid, date, keyBuffer) {
  const uuids = uuid.split("/");
  const buf1 = Buffer.alloc(8);
  const uint16array1 = new Uint8Array(
    buf1.buffer,
    buf1.byteOffset,
    buf1.length / Uint8Array.BYTES_PER_ELEMENT
  );
  buf1.writeBigInt64LE(BigInt(uuids[0]));
  buf1.reverse();
  const buf2 = Buffer.alloc(8);
  const uint16array2 = new Uint8Array(
    buf2.buffer,
    buf2.byteOffset,
    buf2.length / Uint8Array.BYTES_PER_ELEMENT
  );
  buf2.writeBigInt64LE(BigInt(uuids[1]));
  buf2.reverse();
  const buf3 = Buffer.alloc(8);
  const uint16array3 = new Uint8Array(
    buf3.buffer,
    buf3.byteOffset,
    buf3.length / Uint8Array.BYTES_PER_ELEMENT
  );
  buf3.writeBigInt64LE(BigInt(date));
  buf3.reverse();
  const uint16array4 = new Uint8Array(
    keyBuffer.buffer,
    keyBuffer.byteOffset,
    keyBuffer.length / Uint8Array.BYTES_PER_ELEMENT
  );
  const buffer = Buffer.concat([uint16array1, uint16array2, uint16array3, uint16array4]);
  const int16array = new Int8Array(
    buffer.buffer,
    buffer.byteOffset,
    buffer.length / Int8Array.BYTES_PER_ELEMENT
  );
  return int16array;
}


function toUuidString(uuidBitsString) {
  const digits = (val, ds) => {
    const hi = 1n << (ds * 4n);
    return (hi | (val & (hi - 1n))).toString(16).substring(1);
  }

  const msb = BigInt(uuidBitsString.split('/')[0]);
  const lsb = BigInt(uuidBitsString.split('/')[1]); 

  return digits(msb >> 32n, 8n) + digits(msb >> 16n, 4n) + digits(msb, 4n) + digits(lsb >> 48n, 4n) + digits(lsb, 12n);
}