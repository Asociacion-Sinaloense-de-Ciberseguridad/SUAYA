import { createHash, createCipheriv, generateKeyPairSync } from "node:crypto";
import https from "node:https";

export const huella = (d: Buffer) => createHash("sha1").update(d).digest("hex");
export const cifrador = (k: Buffer, iv: Buffer) => createCipheriv("aes-256-gcm", k, iv);
export const par = () => generateKeyPairSync("rsa", { modulusLength: 3072 });
export const agente = new https.Agent({ rejectUnauthorized: false });
