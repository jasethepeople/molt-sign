import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const toolPath = fileURLToPath(new URL('../molt-sign.mjs', import.meta.url));
const PRIVATE_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const PUBLIC_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function freshPair() {
  const pair = generateKeyPairSync('ed25519');
  const privateDer = Buffer.from(pair.privateKey.export({ format: 'der', type: 'pkcs8' }));
  const publicDer = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }));
  return {
    privateKeyHex: privateDer.subarray(-32).toString('hex'),
    publicKeyHex: publicDer.subarray(-32).toString('hex'),
  };
}

function run(args, input) {
  const result = spawnSync(process.execPath, [toolPath, ...args], { input, maxBuffer: 1024 * 1024 });
  if (result.error) throw result.error;
  return {
    status: result.status,
    stdout: result.stdout.toString('utf8'),
    stderr: result.stderr.toString('utf8'),
  };
}

async function temporaryDirectory(t) {
  const directory = await mkdtemp(join(tmpdir(), 'molt-sign-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

async function writeManifestIdentity(directory, pair, name = 'identity.json') {
  const identityPath = join(directory, name);
  await writeFile(identityPath, JSON.stringify({ 'manifest-signer': { priv: pair.privateKeyHex, pub: pair.publicKeyHex } }), { mode: 0o600 });
  return identityPath;
}

async function writeBytes(directory, bytes, name = 'message.bin') {
  const inputPath = join(directory, name);
  await writeFile(inputPath, bytes);
  return inputPath;
}

function signWithFile(identityPath, inputPath) {
  return run(['sign', '--key', identityPath, '--in', inputPath]);
}

function assertSignPass(result) {
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^[a-f0-9]{128}\n$/);
  assert.equal(result.stderr, '');
}

function verifyWithStdin(publicKeyHex, signatureHex, bytes) {
  return run(['verify', '--pub', publicKeyHex, '--sig', signatureHex], bytes);
}

test('round-trip signs and verifies the exact message bytes', async (t) => {
  const directory = await temporaryDirectory(t);
  const pair = freshPair();
  const bytes = Buffer.from('{"a":1,"b":2}');
  const identityPath = await writeManifestIdentity(directory, pair);
  const inputPath = await writeBytes(directory, bytes);
  const signed = signWithFile(identityPath, inputPath);
  assertSignPass(signed);
  const verified = verifyWithStdin(pair.publicKeyHex, signed.stdout.trim(), bytes);
  assert.equal(verified.status, 0);
  assert.equal(verified.stdout, 'PASS\n');
});

test('tampered message fails verification', async (t) => {
  const directory = await temporaryDirectory(t);
  const pair = freshPair();
  const identityPath = await writeManifestIdentity(directory, pair);
  const original = Buffer.from('{"a":1,"b":2}');
  const inputPath = await writeBytes(directory, original);
  const signed = signWithFile(identityPath, inputPath);
  assertSignPass(signed);
  const tampered = Buffer.from(original);
  tampered[5] ^= 1;
  const result = verifyWithStdin(pair.publicKeyHex, signed.stdout.trim(), tampered);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, 'FAIL\n');
});

test('tampered signature fails verification', async (t) => {
  const directory = await temporaryDirectory(t);
  const pair = freshPair();
  const identityPath = await writeManifestIdentity(directory, pair);
  const bytes = Buffer.from('signature fixture');
  const inputPath = await writeBytes(directory, bytes);
  const signed = signWithFile(identityPath, inputPath);
  assertSignPass(signed);
  const signature = signed.stdout.trim();
  const tampered = `${signature[0] === '0' ? '1' : '0'}${signature.slice(1)}`;
  const result = verifyWithStdin(pair.publicKeyHex, tampered, bytes);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, 'FAIL\n');
});

test('a different public key fails verification', async (t) => {
  const directory = await temporaryDirectory(t);
  const signer = freshPair();
  const other = freshPair();
  const identityPath = await writeManifestIdentity(directory, signer);
  const bytes = Buffer.from('wrong key fixture');
  const inputPath = await writeBytes(directory, bytes);
  const signed = signWithFile(identityPath, inputPath);
  assertSignPass(signed);
  const result = verifyWithStdin(other.publicKeyHex, signed.stdout.trim(), bytes);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, 'FAIL\n');
});

test('manifest-signer identity shape is accepted by the CLI', async (t) => {
  const directory = await temporaryDirectory(t);
  const pair = freshPair();
  const identityPath = await writeManifestIdentity(directory, pair);
  const bytes = Buffer.from('manifest-signer format');
  const inputPath = await writeBytes(directory, bytes);
  const signed = signWithFile(identityPath, inputPath);
  assertSignPass(signed);
  const result = verifyWithStdin(pair.publicKeyHex, signed.stdout.trim(), bytes);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'PASS\n');
});

test('molt.ed25519-identity.v1 identity shape is accepted by the CLI', async (t) => {
  const directory = await temporaryDirectory(t);
  const pair = freshPair();
  const identityPath = join(directory, 'identity-v1.json');
  const keyId = createHash('sha256').update(Buffer.from(pair.publicKeyHex, 'hex')).digest('hex');
  await writeFile(identityPath, JSON.stringify({
    schema: 'molt.ed25519-identity.v1',
    algorithm: 'Ed25519',
    purpose: 'TEST-ONLY',
    privateKeyHex: pair.privateKeyHex,
    publicKeyHex: pair.publicKeyHex,
    keyId,
  }), { mode: 0o600 });
  const bytes = Buffer.from('v1 identity format');
  const inputPath = await writeBytes(directory, bytes);
  const signed = signWithFile(identityPath, inputPath);
  assertSignPass(signed);
  const result = verifyWithStdin(pair.publicKeyHex, signed.stdout.trim(), bytes);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'PASS\n');
});

test('mismatched identity fails without printing a signature', async (t) => {
  const directory = await temporaryDirectory(t);
  const signer = freshPair();
  const other = freshPair();
  const identityPath = await writeManifestIdentity(directory, { ...signer, publicKeyHex: other.publicKeyHex });
  const inputPath = await writeBytes(directory, Buffer.from('should not sign'));
  const result = signWithFile(identityPath, inputPath);
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /does not match the stated public key/);
});

test('verify CLI exit codes and output are PASS/0 and FAIL/1', async (t) => {
  const directory = await temporaryDirectory(t);
  const pair = freshPair();
  const identityPath = await writeManifestIdentity(directory, pair);
  const bytes = Buffer.from('cli exit fixture');
  const inputPath = await writeBytes(directory, bytes);
  const signed = signWithFile(identityPath, inputPath);
  assertSignPass(signed);
  const signature = signed.stdout.trim();
  const good = run(['verify', '--pub', pair.publicKeyHex, '--in', inputPath, '--sig', signature]);
  assert.equal(good.status, 0);
  assert.equal(good.stdout, 'PASS\n');
  const badSignature = `${signature[0] === '0' ? '1' : '0'}${signature.slice(1)}`;
  const bad = run(['verify', '--pub', pair.publicKeyHex, '--in', inputPath, '--sig', badSignature]);
  assert.equal(bad.status, 1);
  assert.equal(bad.stdout, 'FAIL\n');
});

test('empty input signs and verifies successfully', async (t) => {
  const directory = await temporaryDirectory(t);
  const pair = freshPair();
  const identityPath = await writeManifestIdentity(directory, pair);
  const inputPath = await writeBytes(directory, Buffer.alloc(0));
  const signed = signWithFile(identityPath, inputPath);
  assertSignPass(signed);
  const result = verifyWithStdin(pair.publicKeyHex, signed.stdout.trim(), Buffer.alloc(0));
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'PASS\n');
});

test('stdin input is signed byte-for-byte and verifies from stdin', async (t) => {
  const directory = await temporaryDirectory(t);
  const pair = freshPair();
  const identityPath = await writeManifestIdentity(directory, pair);
  const bytes = Buffer.from([0x00, 0xff, 0x0a, 0x7b, 0x7d]);
  const signed = run(['sign', '--key', identityPath], bytes);
  assertSignPass(signed);
  const result = verifyWithStdin(pair.publicKeyHex, signed.stdout.trim(), bytes);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'PASS\n');
});

test('RFC 8032 Ed25519 test vector 1 signs the empty message exactly', () => {
  const seedHex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
  const publicHex = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
  const signatureHex = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' +
    '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';
  const privateKey = createPrivateKey({
    key: Buffer.concat([PRIVATE_PREFIX, Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey({
    key: Buffer.concat([PUBLIC_PREFIX, Buffer.from(publicHex, 'hex')]),
    format: 'der',
    type: 'spki',
  });
  const actualPublic = Buffer.from(publicKey.export({ format: 'der', type: 'spki' })).subarray(-32).toString('hex');
  const actualSignature = sign(null, Buffer.alloc(0), privateKey).toString('hex');
  assert.equal(actualPublic, publicHex);
  assert.equal(actualSignature, signatureHex);
  assert.equal(verify(null, Buffer.alloc(0), publicKey, Buffer.from(signatureHex, 'hex')), true);
});

test('malformed flags, hex, and missing files fail without stdout output', async (t) => {
  const directory = await temporaryDirectory(t);
  const pair = freshPair();
  const identityPath = await writeManifestIdentity(directory, pair);
  const bytes = Buffer.from('invalid input checks');
  const inputPath = await writeBytes(directory, bytes);
  const signed = signWithFile(identityPath, inputPath);
  assertSignPass(signed);
  const signature = signed.stdout.trim();
  const results = [
    run(['verify', '--pub', 'z'.repeat(64), '--in', inputPath, '--sig', signature]),
    run(['verify', '--pub', pair.publicKeyHex, '--in', inputPath, '--sig', 'ab']),
    run(['verify', '--pub', pair.publicKeyHex, '--in', join(directory, 'missing.bin'), '--sig', signature]),
    run(['sign', '--key', identityPath, '--in', join(directory, 'missing.bin')]),
    run(['verify', '--pub', pair.publicKeyHex, '--sig', signature, '--unknown', 'value']),
  ];
  for (const result of results) {
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, '');
    assert.notEqual(result.stderr, '');
  }
});
