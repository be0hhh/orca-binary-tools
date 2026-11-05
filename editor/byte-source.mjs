/** All binary consumers use byteLength/version/read; backing storage never leaks. */
export const MAX_FILE_BYTES = 1024 * 1024 * 1024;
const PAGE = 65536;
export const SCAN_BYTES = 262144;
const CACHE_BYTES = 4 * 1024 * 1024;
export function cancelled(signal) {
  if (signal?.aborted) throw Object.assign(new Error('Analysis cancelled'), { name: 'AbortError' });
}
export function changed() {
  return Object.assign(new Error('File changed. Reload to inspect the new version.'), { code: 'FILE_CHANGED' });
}
function range(size, offset, length) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset > size || length > size - offset)
    throw new RangeError('Invalid byte range');
}
function sizeLimit(size) {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_FILE_BYTES)
    throw new RangeError('This file exceeds the 1 GiB inspection limit. No data was truncated or opened.');
}
export function bytesSource(bytes) {
  if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
  sizeLimit(bytes.byteLength);
  return { byteLength: bytes.byteLength, version: 0, async read(offset, length, { signal } = {}) {
    cancelled(signal); range(bytes.byteLength, offset, length);
    return bytes.subarray(offset, offset + length);
  } };
}
export function fileSource(file) {
  sizeLimit(file.size);
  return { byteLength: file.size, version: 0, async read(offset, length, { signal } = {}) {
    cancelled(signal); range(file.size, offset, length);
    const blob = file.slice(offset, offset + length);
    const buffer = typeof blob.arrayBuffer === 'function' ? await blob.arrayBuffer() : await new Promise((resolve, reject) => {
      const reader = new FileReader();
      const cancel = () => { reader.abort(); reject(Object.assign(new Error('Analysis cancelled'), { name: 'AbortError' })); };
      signal?.addEventListener('abort', cancel, { once: true });
      reader.onload = () => { signal?.removeEventListener('abort', cancel); resolve(reader.result); };
      reader.onerror = () => { signal?.removeEventListener('abort', cancel); reject(reader.error); };
      reader.readAsArrayBuffer(blob);
    });
    cancelled(signal); return new Uint8Array(buffer);
  } };
}
export function rangeSource(session, descriptor = session.value) {
  sizeLimit(descriptor.byteLength);
  const { byteLength, version, maxReadBytes } = descriptor;
  if (!Number.isSafeInteger(version) || !Number.isSafeInteger(maxReadBytes) || maxReadBytes < 1 || descriptor.readOnly !== true)
    throw new Error('Invalid range session descriptor');
  return { byteLength, version, async read(offset, length, { signal } = {}) {
    cancelled(signal); range(byteLength, offset, length);
    if (!length) return new Uint8Array(0);
    const readLimit = Math.min(maxReadBytes, SCAN_BYTES);
    const result = length > readLimit ? new Uint8Array(length) : null;
    for (let p = 0; p < length; ) {
      const n = Math.min(length - p, readLimit);
      let reply;
      try { reply = await session.readRange({ version, offset: offset + p, length: n }, { signal }); }
      catch (error) {
        cancelled(signal);
        if (error.code === 'conflict' || error.code === 'action_failed') throw changed();
        throw error;
      }
      cancelled(signal);
      if (reply.version !== version) throw changed();
      if (!(reply.bytes instanceof ArrayBuffer) || reply.bytes.byteLength !== n || reply.eof !== (offset + p + n === byteLength))
        throw new Error('Incomplete or invalid range response');
      const bytes = new Uint8Array(reply.bytes);
      if (!result) return bytes;
      result.set(bytes, p); p += n;
    }
    return result;
  } };
}
/** 64 KiB pages, 4 MiB LRU; sequential 256 KiB scans bypass retention. */
export function pagedSource(input) {
  if (input?.invalidate) return input;
  const backing = input?.read ? input : bytesSource(input);
  sizeLimit(backing.byteLength);
  let invalid = false, active = 0, cached = 0;
  const pages = new Map(), waiters = [];
  const lifetime = new AbortController();
  function check(signal) { cancelled(signal); if (invalid) throw changed(); backing.check?.(signal); }
  async function raw(offset, length, signal) {
    check(signal);
    while (active >= 2) {
      await new Promise((resolve) => {
        const wake = () => {
          const index = waiters.indexOf(wake);
          if (index >= 0) waiters.splice(index, 1);
          signal?.removeEventListener('abort', wake); resolve();
        };
        waiters.push(wake); signal?.addEventListener('abort', wake, { once: true });
      }); check(signal);
    }
    active++;
    const linked = new AbortController();
    const stop = () => linked.abort();
    signal?.addEventListener('abort', stop, { once: true });
    lifetime.signal.addEventListener('abort', stop, { once: true });
    try {
      check(signal);
      const value = await backing.read(offset, length, { signal: linked.signal });
      check(signal);
      if (!(value instanceof Uint8Array) || value.byteLength !== length) throw new Error('Incomplete byte range');
      return value;
    } finally {
      signal?.removeEventListener('abort', stop);
      lifetime.signal.removeEventListener('abort', stop);
      active--; waiters.splice(0).forEach((wake) => wake());
    }
  }
  async function page(index, signal) {
    check(signal);
    if (pages.has(index)) { const p = pages.get(index); pages.delete(index); pages.set(index, p); return p; }
    // Each consumer owns cancellation; do not share an in-flight read's AbortSignal.
    const offset = index * PAGE, length = Math.min(PAGE, backing.byteLength - offset);
    const value = await raw(offset, length, signal);
    check(signal);
    if (!pages.has(index)) { pages.set(index, value); cached += value.byteLength; }
    while (cached > CACHE_BYTES) { const key = pages.keys().next().value; cached -= pages.get(key).byteLength; pages.delete(key); }
    return value;
  }
  return { byteLength: backing.byteLength, version: backing.version,
    check,
    invalidate() { invalid = true; lifetime.abort(); pages.clear(); cached = 0; waiters.splice(0).forEach((wake) => wake()); },
    async read(offset, length, { signal } = {}) {
      check(signal); range(backing.byteLength, offset, length);
      if (length > SCAN_BYTES) throw new RangeError("Read exceeds 256 KiB; scan in chunks");
      if (!length) return new Uint8Array(0);
      if (length >= PAGE) return raw(offset, length, signal);
      const first = Math.floor(offset / PAGE), last = Math.floor((offset + length - 1) / PAGE);
      const a = await page(first, signal);
      check(signal);
      if (first === last) return a.subarray(offset % PAGE, offset % PAGE + length);
      const b = await page(last, signal), result = new Uint8Array(length), split = PAGE - offset % PAGE;
      result.set(a.subarray(offset % PAGE)); result.set(b.subarray(0, length - split), split);
      check(signal); return result;
    }
  };
}
export function subSource(source, offset, length) {
  range(source.byteLength, offset, length);
  const view = { byteLength: length, version: source.version, check: (signal) => source.check?.(signal),
    async read(position, count, options = {}) {
      range(length, position, count); return source.read(offset + position, count, options);
    } };
  // Members share their prepared owner's cache, concurrency and invalidation lifetime.
  if (typeof source.invalidate === 'function') view.invalidate = () => source.invalidate();
  return view;
}
