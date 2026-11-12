#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const PRIVATE_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const PUBLIC_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const HEX_32 = /^[0-9a-f]{64}$/;
const HEX_64 = /^[0-9a-f]{128}$/;

function fail(message) {
  throw new Error(message);
}

function usage() {
  return "Usage: node molt-sign.mjs sign --key KEYFILE [--in FILE] | node molt-sign.mjs verify --pub PUBHEX --sig SIGHEX [--in FILE]";
}

function parseArgs(argv) {
  const command = argv[0];
  if (command !== "sign" && command !== "verify") fail(`Invalid command. ${usage()}`);
  const allowed = command === "sign" ? new Set(["--key", "--in"]) : new Set(["--pub", "--sig", "--in"]);
  const options = new Map();
  for (let i = 1; i < argv.length; i += 1) {
    const flag = argv[i];
    if (!allowed.has(flag)) fail(`Unknown or unsupported flag: ${flag}. ${usage()}`);
    if (options.has(flag)) fail(`Duplicate flag: ${flag}.`);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--")) fail(`Missing value for ${flag}.`);
    options.set(flag, value);
    i += 1;
  }
  if (command === "sign" && !options.has("--key")) fail(`Missing required --key. ${usage()}`);
  if (command === "verify" && (!options.has("--pub") || !options.has("--sig"))) fail(`Verify requires --pub and --sig. ${usage()}`);
  return { command, options };
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks);
}

async function readInput(path) {
  try {
    return path === undefined ? await readStdin() : await readFile(path);
  } catch {
    fail(path === undefined ? "Unable to read bytes from stdin." : `Unable to read input file: ${path}`);
  }
}

function rawPublicKey(publicKey) {
  return Buffer.from(publicKey.export({ format: "der", type: "spki" })).subarray(-32);
}

function privateKeyFromSeed(seed) {
  return createPrivateKey({ key: Buffer.concat([PRIVATE_PREFIX, seed]), format: "der", type: "pkcs8" });
}

function publicKeyFromRaw(rawKey) {
  return createPublicKey({ key: Buffer.concat([PUBLIC_PREFIX, rawKey]), format: "der", type: "spki" });
}

function requireHex(value, expression, label) {
  if (!expression.test(value)) fail(`${label} must be lowercase hexadecimal of the required length.`);
  return Buffer.from(value, "hex");
}

async function readIdentity(path) {
  let identity;
  try {
    identity = JSON.parse(await readFile(path, "utf8"));
  } catch {
    fail("Identity file is not readable JSON.");
  }
  if (!identity || typeof identity !== "object" || Array.isArray(identity)) fail("Identity file must contain a JSON object.");

  let privateHex;
  let publicHex;
  if (Object.hasOwn(identity, "manifest-signer")) {
    if (Object.keys(identity).length !== 1) fail("Manifest signer identity must have only the manifest-signer top-level property.");
    const signer = identity["manifest-signer"];
    if (!signer || typeof signer !== "object" || Array.isArray(signer) || Object.keys(signer).length !== 2 || !Object.hasOwn(signer, "priv") || !Object.hasOwn(signer, "pub")) {
      fail("Manifest signer identity must contain exactly priv and pub.");
    }
    privateHex = signer.priv;
    publicHex = signer.pub;
  } else {
    if (identity.schema !== "molt.ed25519-identity.v1" || identity.algorithm !== "Ed25519" || typeof identity.purpose !== "string" || !identity.purpose.trim()) {
      fail("Identity file must use the documented molt.ed25519-identity.v1 schema.");
    }
    privateHex = identity.privateKeyHex;
    publicHex = identity.publicKeyHex;
    if (typeof identity.keyId !== "string" || !HEX_32.test(identity.keyId)) fail("Identity keyId must be 64 lowercase hexadecimal characters.");
  }

  if (typeof privateHex !== "string" || typeof publicHex !== "string") fail("Identity private and public keys must be hexadecimal strings.");
  const seed = requireHex(privateHex, HEX_32, "Identity private key");
  const statedPublic = requireHex(publicHex, HEX_32, "Identity public key");
  let privateKey;
  try {
    privateKey = privateKeyFromSeed(seed);
  } catch {
    fail("Identity private key is not a valid Ed25519 seed.");
  }
  const derivedPublic = rawPublicKey(createPublicKey(privateKey));
  if (!derivedPublic.equals(statedPublic)) fail("Identity private key does not match the stated public key.");
  if (!Object.hasOwn(identity, "manifest-signer")) {
    const expectedKeyId = createHash("sha256").update(statedPublic).digest("hex");
    if (identity.keyId !== expectedKeyId) fail("Identity keyId does not match the stated public key.");
  }
  return privateKey;
}

async function main(argv) {
  const { command, options } = parseArgs(argv);
  const bytes = await readInput(options.get("--in"));
  if (command === "sign") {
    let privateKey;
    try {
      privateKey = await readIdentity(options.get("--key"));
    } catch (error) {
      if (error instanceof Error) throw error;
      fail("Unable to read identity file.");
    }
    process.stdout.write(`${sign(null, bytes, privateKey).toString("hex")}\n`);
    return;
  }

  const publicBytes = requireHex(options.get("--pub"), HEX_32, "Public key");
  const signature = requireHex(options.get("--sig"), HEX_64, "Signature");
  let valid = false;
  try {
    valid = verify(null, bytes, publicKeyFromRaw(publicBytes), signature);
  } catch {
    fail("Unable to verify with the supplied Ed25519 public key.");
  }
  process.stdout.write(valid ? "PASS\n" : "FAIL\n");
  if (!valid) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch(error => {
    const message = error instanceof Error ? error.message : "Unexpected failure.";
    process.stderr.write(`molt-sign: ${message}\n`);
    process.exitCode = 2;
  });
}
