/* offscreen.js
   Исполнитель задач скачивания HLS: качает сегменты, расшифровывает AES-128,
   трансмуксит в fMP4 через mux-4.js на лету, патчит duration, отдаёт blob URL наверх
   и ждёт CLEAR.

   Входящие:  START_JOB, CANCEL_JOB, CLEAR, CLEAR_ALL
   Исходящие: JOB_PROGRESS, JOB_DONE, JOB_ERROR, JOB_CANCELLED
*/

/* ============================================================
   Константы
   ============================================================ */

const MAX_CONCURRENT = 3;
const PROGRESS_THROTTLE_MS = 200;
const SEGMENT_RETRY_DELAYS = [500, 1500, 4500];
const SEGMENT_TIMEOUT_MS = 15000;
const KEY_TIMEOUT_MS = 10000;
const JOB_TIMEOUT_MS = 30 * 60 * 1000;

/* ============================================================
   Состояние
   ============================================================ */

const activeJobs = new Map();   // jobId -> JobState
const pendingQueue = [];        // [{ jobId, spec, tabId }]
const keyCache = new Map();     // keyUrl -> { key: CryptoKey, bytes: Uint8Array }

/* ============================================================
   Хелперы
   ============================================================ */

function post(msg) {
  return chrome.runtime.sendMessage(msg).catch(() => {});
}

function sendProgress(jobId, tabId, phase, done, total, bytes) {
  const percent = total > 0 ? Math.floor((done / total) * 100) : 0;
  post({
    type: 'JOB_PROGRESS',
    jobId,
    tabId,
    phase,
    done,
    total,
    bytes,
    percent
  });
}

function sendDone(jobId, tabId, payload) {
  console.log(`[Offscreen] Задача ${jobId} (tab ${tabId}) успешно завершена, размер: ${payload.size} байт`);
  post({
    type: 'JOB_DONE',
    jobId,
    tabId,
    blobUrl: payload.blobUrl,
    size: payload.size,
    // outputName: payload.outputName,
    outputFolder: payload.outputFolder
  });
}

function sendError(jobId, tabId, phase, message, segmentIndex, retryable) {
  console.error(`[Offscreen] Ошибка задачи ${jobId} (tab ${tabId}) в фазе '${phase}':`, message);
  post({
    type: 'JOB_ERROR',
    jobId,
    tabId,
    phase,
    message: String(message),
    segmentIndex: segmentIndex !== undefined ? segmentIndex : null,
    retryable: !!retryable
  });
}

function sendCancelled(jobId, tabId) {
  console.warn(`[Offscreen] Задача ${jobId} (tab ${tabId}) отменена`);
  post({ type: 'JOB_CANCELLED', jobId, tabId });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function hexToBytes(hex) {
  const clean = String(hex).replace(/^0x/, '');
  if (clean.length % 2 !== 0) throw new Error('Bad IV hex length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

function joinUrl(base, name) {
  if (/^https?:\/\//i.test(name)) return name;
  if (base.endsWith('/')) return base + name;
  return base + '/' + name;
}

/* ============================================================
   Fetch с таймаутом, retry и abort
   ============================================================ */

async function fetchOnce(url, headers, timeoutMs, signal) {
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener('abort', onAbort, { once: true });
  }
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      headers: headers || undefined,
      signal: controller.signal
    });
    if (!r.ok) {
      const err = new Error('HTTP ' + r.status + ' ' + url);
      err.status = r.status;
      throw err;
    }
    const buf = await r.arrayBuffer();
    return { buf, contentLength: r.headers.get('Content-Length') };
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

async function fetchWithRetry(url, headers, timeoutMs, signal) {
  let lastErr = null;
  for (let attempt = 0; attempt <= SEGMENT_RETRY_DELAYS.length; attempt++) {
    if (signal && signal.aborted) throw new DOMException('Aborted', 'AbortError');
    try {
      return await fetchOnce(url, headers, timeoutMs, signal);
    } catch (e) {
      if (e && e.name === 'AbortError') throw e;
      lastErr = e;
      if (attempt < SEGMENT_RETRY_DELAYS.length) {
        await sleep(SEGMENT_RETRY_DELAYS[attempt]);
      }
    }
  }
  throw lastErr || new Error('fetch failed: ' + url);
}

/* ============================================================
   Ключ
   ============================================================ */

async function getKey(keyUrl, headers, signal) {
  const cached = keyCache.get(keyUrl);
  if (cached) return cached;

  const { buf } = await fetchWithRetry(keyUrl, headers, KEY_TIMEOUT_MS, signal);
  const bytes = new Uint8Array(buf);
  const key = await crypto.subtle.importKey(
      'raw', bytes, { name: 'AES-CBC' }, false, ['decrypt']
  );
  const entry = { key, bytes };
  keyCache.set(keyUrl, entry);
  return entry;
}

/* ============================================================
   Расшифровка
   ============================================================ */

async function decryptAES128(encrypted, key, ivBytes) {
  const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: ivBytes }, key, encrypted
  );
  return new Uint8Array(decrypted);
}

/* ============================================================
   Патч duration для MP4
   ============================================================ */

function patchInitSegmentDuration(initSegment, initLength, durationSeconds) {
  const view = initSegment.subarray(0, initLength);

  const mvhd = muxjs.mp4.probe.findBox(view, ['moov', 'mvhd'])[0];
  if (mvhd) {
    const dv = new DataView(mvhd.buffer, mvhd.byteOffset, mvhd.byteLength);
    const version = dv.getUint8(0);
    if (version === 0) {
      dv.setUint32(4, 0);
      dv.setUint32(8, 0);
      const timescale = dv.getUint32(12);
      dv.setUint32(16, Math.round(durationSeconds * timescale));
    } else {
      dv.setBigUint64(4, 0n);
      dv.setBigUint64(12, 0n);
      const timescale = dv.getUint32(20);
      dv.setBigUint64(24, BigInt(Math.round(durationSeconds * timescale)));
    }
  }

  const mdhd = muxjs.mp4.probe.findBox(view, ['moov', 'trak', 'mdia', 'mdhd'])[0];
  if (mdhd) {
    const dv = new DataView(mdhd.buffer, mdhd.byteOffset, mdhd.byteLength);
    const version = dv.getUint8(0);
    if (version === 0) {
      dv.setUint32(4, 0);
      dv.setUint32(8, 0);
      const timescale = dv.getUint32(12);
      dv.setUint32(16, Math.round(durationSeconds * timescale));
    } else {
      dv.setBigUint64(4, 0n);
      dv.setBigUint64(12, 0n);
      const timescale = dv.getUint32(20);
      dv.setBigUint64(24, BigInt(Math.round(durationSeconds * timescale)));
    }
  }
}

function assembleMp4(initSegment, mediaChunks, durationSeconds) {
  if (!initSegment) throw new Error('No initSegment produced');
  if (mediaChunks.length === 0) throw new Error('No media chunks produced');

  let total = initSegment.length;
  for (const c of mediaChunks) total += c.length;

  const out = new Uint8Array(total);
  out.set(initSegment, 0);
  let off = initSegment.length;
  for (const c of mediaChunks) {
    out.set(c, off);
    off += c.length;
  }

  patchInitSegmentDuration(out, initSegment.length, durationSeconds);

  return out;
}

/* ============================================================
   Обработка одной задачи
   ============================================================ */

function validateSpec(spec) {
  if (!spec || typeof spec !== 'object') return 'spec is not an object';
  if (!spec.baseUrl) return 'baseUrl is required';
  if (!Array.isArray(spec.segments) || spec.segments.length === 0) {
    return 'segments must be a non-empty array';
  }
  if (!Number.isFinite(spec.duration) || spec.duration <= 0) {
    return 'duration must be positive number';
  }
  if (spec.encMethod === 'AES-128') {
    if (!spec.encKey) return 'encKey is required for AES-128';
    if (!spec.iv) return 'iv is required for AES-128';
  }
  // if (!spec.outputName) return 'outputName is required';
  return null;
}

function normalizeSegments(segments) {
  return segments.map((s) => {
    if (typeof s === 'string') return { name: s };
    if (s && typeof s === 'object' && typeof s.name === 'string') return s;
    throw new Error('Invalid segment entry: ' + JSON.stringify(s));
  });
}

async function runJob(jobId, spec) {
  const state = activeJobs.get(jobId);
  if (!state) return;

  console.log(`[Offscreen] Запуск задачи ${jobId} (tab ${state.tabId})`);

  const ac = new AbortController();
  state.abortController = ac;

  const jobDeadline = setTimeout(() => {
    state.timedOut = true;
    try { ac.abort(); } catch (_) {}
  }, JOB_TIMEOUT_MS);

  const emit = (phase, done, total, bytes) => {
    const now = Date.now();
    const force = phase !== state.lastPhase || done === total;
    if (!force && now - state.lastProgressAt < PROGRESS_THROTTLE_MS) return;
    state.lastProgressAt = now;
    state.lastPhase = phase;
    // Исправлено: передаем state.tabId вторым аргументом
    sendProgress(jobId, state.tabId, phase, done, total, bytes);
  };

  try {
    const segments = normalizeSegments(spec.segments);
    const total = segments.length;
    state.totalSegments = total;

    const transmuxer = new muxjs.mp4.Transmuxer({
      remux: true,
      keepOriginalTimestamps: false
    });

    let initSegment = null;
    const mediaChunks = [];

    transmuxer.on('data', (seg) => {
      if (seg.initSegment && !initSegment) initSegment = seg.initSegment;
      if (seg.data) mediaChunks.push(seg.data);
    });

    transmuxer.on('log', (e) => {
      if (e && e.level === 'warn' && spec.debug) {
        console.warn('[mux]', e.message);
      }
    });

    let key = null;
    let defaultIv = null;
    if (spec.encMethod === 'AES-128') {
      defaultIv = hexToBytes(spec.iv);
      emit('fetching', 0, total, 0);
      try {
        const entry = await getKey(spec.encKey, spec.headers, ac.signal);
        key = entry.key;
      } catch (e) {
        if (e && e.name === 'AbortError') throw e;
        throw Object.assign(new Error('key fetch failed: ' + e.message), { phase: 'fetching' });
      }
    }

    let bytesDownloaded = 0;

    for (let i = 0; i < total; i++) {
      if (state.cancelled) throw new DOMException('Cancelled', 'AbortError');
      const seg = segments[i];
      const url = joinUrl(spec.baseUrl, seg.name);
      let buf;
      try {
        const r = await fetchWithRetry(url, spec.headers, SEGMENT_TIMEOUT_MS, ac.signal);
        buf = r.buf;
        if (r.contentLength && buf.byteLength !== parseInt(r.contentLength, 10)) {
          if (spec.debug) {
            console.warn('[offscreen] content-length mismatch on', seg.name);
          }
        }
      } catch (e) {
        if (e && e.name === 'AbortError') throw e;
        throw Object.assign(
            new Error('segment fetch failed: ' + e.message),
            { phase: 'fetching', segmentIndex: i, retryable: true }
        );
      }

      let dec;
      if (spec.encMethod === 'AES-128') {
        const ivBytes = seg.iv ? hexToBytes(seg.iv) : defaultIv;
        try {
          dec = await decryptAES128(buf, key, ivBytes);
        } catch (e) {
          throw Object.assign(
              new Error('decrypt failed: ' + e.message),
              { phase: 'fetching', segmentIndex: i, retryable: false }
          );
        }
      } else {
        dec = new Uint8Array(buf);
      }

      if (dec.byteLength % 16 !== 0 && spec.encMethod === 'AES-128' && spec.debug) {
        console.warn('[offscreen] decrypted length not multiple of 16:', seg.name);
      }

      try {
        transmuxer.push(dec);
        transmuxer.flush();
      } catch (e) {
        throw Object.assign(
            new Error('mux push failed: ' + e.message),
            { phase: 'muxing', segmentIndex: i, retryable: false }
        );
      }

      bytesDownloaded += dec.byteLength;
      emit('fetching', i + 1, total, bytesDownloaded);
    }

    if (state.cancelled) throw new DOMException('Cancelled', 'AbortError');

    emit('muxing', total, total, bytesDownloaded);

    let fileBytes;
    try {
      fileBytes = assembleMp4(initSegment, mediaChunks, spec.duration);
    } catch (e) {
      throw Object.assign(
          new Error('assembly failed: ' + e.message),
          { phase: 'muxing', retryable: false }
      );
    }

    if (state.cancelled) throw new DOMException('Cancelled', 'AbortError');

    const blob = new Blob([fileBytes], { type: 'audio/mp4' });
    const blobUrl = URL.createObjectURL(blob);
    state.blobUrl = blobUrl;

    // Исправлено: передаем state.tabId вторым аргументом
    sendDone(jobId, state.tabId, {
      blobUrl,
      size: fileBytes.byteLength,
      // outputName: spec.outputName,
      outputFolder: spec.outputFolder || null
    });

  } catch (e) {
    if (e && e.name === 'AbortError') {
      if (state.timedOut) {
        sendError(jobId, state.tabId, state.lastPhase || 'unknown', 'job timed out', null, true);
      } else {
        sendCancelled(jobId, state.tabId);
      }
      cleanupJob(jobId);
      return;
    }
    const phase = e.phase || 'unknown';
    const retryable = e.retryable !== undefined ? e.retryable : (phase === 'fetching');
    // Исправлено: передаем state.tabId вторым аргументом
    sendError(jobId, state.tabId, phase, e.message || String(e), e.segmentIndex, retryable);
    cleanupJob(jobId);
  } finally {
    clearTimeout(jobDeadline);
  }
}

function cleanupJob(jobId) {
  const state = activeJobs.get(jobId);
  if (!state) return;
  console.log(`[Offscreen] Очистка ресурсов для задачи ${jobId} (tab ${state.tabId})`);
  try {
    if (state.abortController) state.abortController.abort();
  } catch (_) {}
  if (state.blobUrl) {
    try { URL.revokeObjectURL(state.blobUrl); } catch (_) {}
  }
  activeJobs.delete(jobId);
  scheduleNext();
}

/* ============================================================
   Пул
   ============================================================ */

function scheduleNext() {
  while (activeJobs.size < MAX_CONCURRENT && pendingQueue.length > 0) {
    const { jobId, spec, tabId } = pendingQueue.shift();
    if (activeJobs.has(jobId)) continue;

    const state = {
      jobId,
      tabId,
      spec,
      cancelled: false,
      timedOut: false,
      lastPhase: null,
      lastProgressAt: 0,
      totalSegments: 0,
      blobUrl: null,
      abortController: null
    };
    activeJobs.set(jobId, state);
    runJob(jobId, spec);
  }
}

/* ============================================================
   Обработчики сообщений
   ============================================================ */

function handleStartJob(msg) {
  const { jobId, spec, tabId } = msg;
  console.log(`[Offscreen] Получена команда START_JOB: ${jobId} для вкладки ${tabId}`);

  if (!jobId) {
    sendError(String(jobId), tabId, 'validation', 'jobId is required', null, false);
    return;
  }
  if (activeJobs.has(jobId) || pendingQueue.some((j) => j.jobId === jobId)) {
    sendError(jobId, tabId, 'validation', 'duplicate jobId', null, false);
    return;
  }
  const err = validateSpec(spec);
  if (err) {
    sendError(jobId, tabId, 'validation', err, null, false);
    return;
  }
  pendingQueue.push({ jobId, spec, tabId });
  scheduleNext();
}

function handleCancelJob(msg) {
  const { jobId, tabId } = msg;
  console.log(`[Offscreen] Получена команда CANCEL_JOB: ${jobId}`);
  if (!jobId) return;

  const idx = pendingQueue.findIndex((j) => j.jobId === jobId);
  if (idx !== -1) {
    pendingQueue.splice(idx, 1);
    sendCancelled(jobId, tabId);
    return;
  }

  const state = activeJobs.get(jobId);
  if (!state) return;
  state.cancelled = true;
  cleanupJob(jobId);
}

function handleClear(msg) {
  const { jobId } = msg;
  console.log(`[Offscreen] Получена команда CLEAR: ${jobId}`);
  if (!jobId) return;

  const idx = pendingQueue.findIndex((j) => j.jobId === jobId);
  if (idx !== -1) pendingQueue.splice(idx, 1);

  cleanupJob(jobId);
}

function handleClearAll() {
  console.log('[Offscreen] Получена команда CLEAR_ALL');
  pendingQueue.length = 0;
  for (const [jobId] of activeJobs) {
    cleanupJob(jobId);
  }
  keyCache.clear();
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type || msg.target !== 'offscreen') return;

  switch (msg.type) {
    case 'START_JOB':
      handleStartJob(msg);
      sendResponse({ ok: true });
      return false;
    case 'CANCEL_JOB':
      handleCancelJob(msg);
      sendResponse({ ok: true });
      return false;
    case 'CLEAR':
      handleClear(msg);
      sendResponse({ ok: true });
      return false;
    case 'CLEAR_ALL':
      handleClearAll();
      sendResponse({ ok: true });
      return false;
    default:
      return;
  }
});