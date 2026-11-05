import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bytesSource, fileSource, rangeSource, pagedSource, subSource, MAX_FILE_BYTES } from '../editor/byte-source.mjs';
import { parseBinary, searchBytes, scanStrings } from '../editor/binary-core.mjs';
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

test('1 GiB inclusive sparse input reads only requested pages and reaches EOF', async () => {
  const reads = [];
  const source = pagedSource(rangeSource({ value: { version: 9, byteLength: MAX_FILE_BYTES, maxReadBytes: 262144, readOnly: true },
    async readRange({ version, offset, length }) {
      reads.push([offset, length]);
      const bytes = new Uint8Array(length);
      if (offset + length === MAX_FILE_BYTES) bytes[length - 1] = 0xab;
      return { version, bytes: bytes.buffer, eof: offset + length === MAX_FILE_BYTES };
    } }));
  assert.equal((await parseBinary(source)).fileSize, MAX_FILE_BYTES);
  assert.deepEqual([...await source.read(MAX_FILE_BYTES - 3, 3)], [0, 0, 0xab]);
  assert.ok(reads.reduce((n, [, length]) => n + length, 0) <= 131072);
  assert.throws(() => rangeSource({ value: { version: 1, byteLength: MAX_FILE_BYTES + 1, maxReadBytes: 262144, readOnly: true }, readRange() { assert.fail('must reject before payload'); } }), /1 GiB/);
  assert.throws(() => fileSource({ size: MAX_FILE_BYTES + 1, slice() { assert.fail('must reject before payload'); } }), /1 GiB/);
  await assert.rejects(source.read(MAX_FILE_BYTES, 1), /range/);
  assert.equal((await source.read(MAX_FILE_BYTES, 0)).length, 0);
});

test('bounded LRU evicts old pages and limits concurrent backing requests to two', async () => {
  let active = 0, maximum = 0;
  const reads = [];
  const source = pagedSource({ byteLength: 80 * 65536, version: 1, async read(offset, length) {
    maximum = Math.max(maximum, ++active); reads.push(offset); await tick(); active--;
    return new Uint8Array(length).fill(offset / 65536);
  } });
  await Promise.all([0, 1, 2, 3].map((page) => source.read(page * 65536, 1)));
  assert.equal(maximum, 2);
  for (let page = 4; page < 70; page++) await source.read(page * 65536, 1);
  const count = reads.length;
  assert.equal((await source.read(69 * 65536, 1))[0], 69);
  assert.equal(reads.length, count);
  assert.equal((await source.read(0, 1))[0], 0);
  assert.equal(reads.length, count + 1);
});

test('file slices and archive subranges use bounded exact byte coordinates', async () => {
  const data = Uint8Array.from({ length: 100 }, (_, i) => i), reads = [];
  const source = fileSource({ size: data.length, slice(offset, end) {
    reads.push([offset, end]); return { async arrayBuffer() { return data.slice(offset, end).buffer; } };
  } });
  const member = subSource(source, 31, 17);
  assert.deepEqual([...await member.read(5, 3)], [36, 37, 38]);
  assert.deepEqual(reads, [[36, 39]]);
  await assert.rejects(member.read(16, 2), /range/);
  assert.deepEqual([...await bytesSource(data).read(97, 3)], [97, 98, 99]);
});

test('stale versions, incomplete reads and invalidation never return mixed bytes', async () => {
  const descriptor = { version: 1, byteLength: 8, maxReadBytes: 4, readOnly: true };
  await assert.rejects(rangeSource({ value: descriptor, async readRange() { return { version: 2, bytes: new ArrayBuffer(4), eof: false }; } }).read(0, 4), { code: 'FILE_CHANGED' });
  await assert.rejects(rangeSource({ value: descriptor, async readRange() { return { version: 1, bytes: new ArrayBuffer(3), eof: false }; } }).read(0, 4), /Incomplete/);
  let finish;
  const source = pagedSource({ byteLength: 8, version: 1, read: () => new Promise((resolve) => { finish = resolve; }) });
  const pending = source.read(0, 1);
  source.invalidate(); finish(new Uint8Array(8));
  await assert.rejects(pending, { code: 'FILE_CHANGED' });
  await assert.rejects(source.read(0, 1), { code: 'FILE_CHANGED' });
  await assert.rejects(parseBinary(source), { code: 'FILE_CHANGED' });
  await assert.rejects(searchBytes(source, '00'), { code: 'FILE_CHANGED' });
  await assert.rejects(scanStrings(source), { code: 'FILE_CHANGED' });
});

test('abort reaches active host reads and queued reads cannot publish late results', async () => {
  const controllers = [], source = pagedSource({ byteLength: 4 * 65536, version: 1, read(offset, length, { signal }) {
    controllers.push(signal);
    return new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(Object.assign(new Error('cancelled'), { name: 'AbortError' })), { once: true }));
  } });
  const ac = new AbortController();
  const requests = [0, 65536, 131072].map((offset) => source.read(offset, 1, { signal: ac.signal }));
  ac.abort();
  const results = await Promise.allSettled(requests);
  assert.equal(controllers.length, 2);
  assert.ok(controllers.every((signal) => signal.aborted));
  assert.ok(results.every((result) => result.status === 'rejected' && result.reason.name === 'AbortError'));
});

test('host conflict errors and ancestor invalidation propagate through cached archive sources', async () => {
  const source = rangeSource({ value: { version: 1, byteLength: 8, maxReadBytes: 262144, readOnly: true },
    async readRange() { throw Object.assign(new Error('unavailable'), { code: 'conflict' }); } });
  await assert.rejects(source.read(0, 4), { code: 'FILE_CHANGED' });
  const root = pagedSource(bytesSource(new Uint8Array(64))), member = pagedSource(subSource(root, 8, 16));
  await member.read(0, 1);
  root.invalidate();
  await assert.rejects(member.read(0, 1), { code: 'FILE_CHANGED' });
});

test('queued cancellation completes while uncancellable backing reads remain pending', async () => {
  const finish = [];
  const source = pagedSource({ byteLength: 3 * 65536, version: 1, read(offset, length) {
    return new Promise((resolve) => { finish.push(() => resolve(new Uint8Array(length))); });
  } });
  const first = source.read(0, 1), second = source.read(65536, 1), ac = new AbortController();
  const queued = source.read(131072, 1, { signal: ac.signal });
  ac.abort();
  await assert.rejects(queued, { name: 'AbortError' });
  assert.equal(finish.length, 2);
  finish.forEach((resolve) => resolve());
  await Promise.all([first, second]);
});

test('archive parser reuses prepared parent pages and shares owner invalidation lifetime', async () => {
  let available = true;
  const source = pagedSource({ byteLength: 131072, version: 1, async read(offset, length) {
    if (!available) throw new Error('backend temporarily unavailable');
    return new Uint8Array(length);
  } });
  await source.read(68, 64);
  const member = pagedSource(subSource(source, 68, 100000));
  const sibling = pagedSource(subSource(source, 8, 16));
  available = false;
  assert.equal((await parseBinary(member)).format, 'RAW');
  await assert.rejects(source.read(65536, 1), /temporarily unavailable/);
  member.invalidate();
  await assert.rejects(source.read(68, 1), { code: 'FILE_CHANGED' });
  await assert.rejects(sibling.read(0, 1), { code: 'FILE_CHANGED' });
  await assert.rejects(parseBinary(member), { code: 'FILE_CHANGED' });
});
