// In-memory Helia node
import { createHelia, type Helia } from "helia";
import { unixfs, type UnixFS } from "@helia/unixfs";
import { MemoryBlockstore } from "blockstore-core";
import { MemoryDatastore } from "datastore-core";

let _helia: Helia | null = null;
let _fs: UnixFS | null = null;

/** Lazily create (or reuse) a single Helia node for this process. */
export async function getNode(): Promise<{ helia: Helia; fs: UnixFS }> {
  if (_helia && _fs) return { helia: _helia, fs: _fs };

  const blockstore = new MemoryBlockstore();
  const datastore = new MemoryDatastore();

  _helia = await createHelia({ blockstore, datastore, start: false });
  _fs = unixfs(_helia);

  return { helia: _helia, fs: _fs };
}

/** Stop the Helia node. */
export async function stopNode(): Promise<void> {
  if (_helia) {
    await _helia.stop();
    _helia = null;
    _fs = null;
  }
}

/**
 * Aggiunge bytes/stringa a IPFS e restituisce il CID come stringa.
 */
export async function addFile(content: string | Uint8Array): Promise<string> {
  const { fs } = await getNode();

  const bytes =
    typeof content === "string" ? new TextEncoder().encode(content) : content;

  const cid = await fs.addBytes(bytes);

  return cid.toString();
}

/**
 * Recupera bytes grezzi da IPFS tramite CID.
 */
export async function getFile(cidStr: string): Promise<Uint8Array> {
  const { fs } = await getNode();

  const cidPath = String(cidStr).trim();

  if (cidPath.length === 0) {
    throw new Error("CID vuoto o non valido");
  }

  const chunks: Uint8Array[] = [];

  for await (const chunk of fs.cat(cidPath)) {
    chunks.push(chunk);
  }

  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);

  let off = 0;

  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }

  return out;
}

/**
 * Recupera il contenuto IPFS come stringa UTF-8.
 */
export async function getFileAsString(cidStr: string): Promise<string> {
  const bytes = await getFile(cidStr);
  return new TextDecoder().decode(bytes);
}

/**
 * Legge un file dal disco e lo carica su IPFS.
 */
export async function addFileFromDisk(filePath: string): Promise<string> {
  const { readFile } = await import("node:fs/promises");
  const bytes = await readFile(filePath);

  return addFile(
    new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  );
}

/**
 * Recupera un file da IPFS e lo salva su disco.
 */
export async function saveFileToDisk(
  cidStr: string,
  outPath: string
): Promise<number> {
  const { writeFile } = await import("node:fs/promises");

  const bytes = await getFile(cidStr);
  await writeFile(outPath, bytes);

  return bytes.length;
}