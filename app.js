/**
 * SALIST ENCRYPT — CORE APPLICATION CONTROLLER
 * Monochromatic Minimalist Apple Architecture (Zero Blur, Crisp Solid Panels)
 * Preserves 100% Cryptographic Compatibility & Offline Static Operations
 */

(function () {
    'use strict';

    // --- STATE VARIABLES ---
    let mode = 'text';
    let imgData = null;
    let stegoImgData = null;
    let selectedFiles = [];
    let encryptedFileBlob = null;
    let decryptedFileBlob = null;
    let decryptedFileName = "decrypted_file";

    const MARKER = "SALIST";
    const MARKER_V4 = "SALISTv4";
    const WM = [83, 65, 76, 73, 83, 84, 50, 48, 50, 53];
    const MAX_FILE = 50 * 1024 * 1024;
    const isTg = !!(window.Telegram && window.Telegram.WebApp);

    // --- UTILITIES ---
    function s(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }
    function $(id) { return document.getElementById(id); }
    function $$(sel) { return document.querySelectorAll(sel); }

    // --- MODERN CRYPTOGRAPHY: Web Crypto AES-256-GCM + PBKDF2 (250,000 iter) ---
    async function deriveKey(password, salt) {
        const keyMaterial = await crypto.subtle.importKey(
            "raw", new TextEncoder().encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
        );
        return await crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: salt, iterations: 250000, hash: "SHA-256" },
            keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
        );
    }

    async function aesGcmEncrypt(plainBytes, password) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveKey(password, salt);
        const cipherBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, plainBytes);
        const cipherBytes = new Uint8Array(cipherBuffer);

        // Container: [Magic (8B: SALISTv4)] + [Salt (16B)] + [IV (12B)] + [Ciphertext + Tag]
        const magic = new TextEncoder().encode("SALISTv4");
        const result = new Uint8Array(8 + 16 + 12 + cipherBytes.length);
        result.set(magic, 0);
        result.set(salt, 8);
        result.set(iv, 24);
        result.set(cipherBytes, 36);
        return result;
    }

    async function aesGcmDecrypt(containerBytes, password) {
        const magicStr = new TextDecoder().decode(containerBytes.subarray(0, 8));
        if (magicStr !== "SALISTv4") throw new Error("Invalid V4 Container");
        const salt = containerBytes.subarray(8, 24);
        const iv = containerBytes.subarray(24, 36);
        const cipherBytes = containerBytes.subarray(36);
        const key = await deriveKey(password, salt);
        const plainBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, cipherBytes);
        return new Uint8Array(plainBuffer);
    }

    // Multi-Layer Cascaded V4 Encrypt & Decrypt
    async function multiLayerV4Encrypt(plainBytes, keys) {
        let data = plainBytes;
        for (const k of keys) {
            data = await aesGcmEncrypt(data, k);
        }
        return data;
    }

    async function multiLayerV4Decrypt(cipherBytes, keys) {
        let data = cipherBytes;
        for (let i = keys.length - 1; i >= 0; i--) {
            data = await aesGcmDecrypt(data, keys[i]);
        }
        return data;
    }

    // --- ULTRA-COMPACT TEXT CIPHER (Minimal Output Length ~ Input Length) ---
    function compactEncrypt(plainBytes, keys) {
        let data = plainBytes;
        for (const k of keys) {
            let keyBig = 0n;
            for (let i = 0; i < k.length; i++) {
                keyBig = (keyBig << 5n) - keyBig + BigInt(k.charCodeAt(i));
            }
            const sc = new SC(keyBig || 123456789n);
            data = sc.enc(data);
        }
        const crc = SalistZip.crc32(plainBytes) & 0xFFFF;
        const res = new Uint8Array(data.length + 2);
        res.set(data, 0);
        res[data.length] = (crc >> 8) & 0xFF;
        res[data.length + 1] = crc & 0xFF;
        return res;
    }

    function compactDecrypt(cipherWithCrc, keys) {
        if (cipherWithCrc.length < 2) throw new Error("Too short");
        const dataLen = cipherWithCrc.length - 2;
        const cipherBytes = cipherWithCrc.subarray(0, dataLen);
        const expectedCrc = (cipherWithCrc[dataLen] << 8) | cipherWithCrc[dataLen + 1];

        let data = cipherBytes;
        for (let i = keys.length - 1; i >= 0; i--) {
            const k = keys[i];
            let keyBig = 0n;
            for (let j = 0; j < k.length; j++) {
                keyBig = (keyBig << 5n) - keyBig + BigInt(k.charCodeAt(j));
            }
            const sc = new SC(keyBig || 123456789n);
            data = sc.dec(data);
        }

        const calcCrc = SalistZip.crc32(data) & 0xFFFF;
        const verified = (calcCrc === expectedCrc);
        return { data, verified };
    }

    // Legacy Stream Cipher
    class SC {
        constructor(k) { this.k = BigInt(k); this.s = this.init(); }
        init() {
            let s = [];
            for (let i = 0; i < 256; i++) s[i] = i;
            let j = 0, k = this.k;
            for (let i = 0; i < 256; i++) {
                j = (j + s[i] + Number(k & 0xFFn)) % 256;
                k = k >> 8n;
                [s[i], s[j]] = [s[j], s[i]];
            }
            return s;
        }
        prga(n) {
            let s = [...this.s], i = 0, j = 0, o = [];
            for (let c = 0; c < n; c++) {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                [s[i], s[j]] = [s[j], s[i]];
                o.push(s[(s[i] + s[j]) % 256]);
            }
            return o;
        }
        enc(d) {
            const b = typeof d === 'string' ? new TextEncoder().encode(d) : d;
            const k = this.prga(b.length);
            const r = new Uint8Array(b.length);
            for (let i = 0; i < b.length; i++) r[i] = b[i] ^ k[i];
            return r;
        }
        dec(d) { return this.enc(d); }
    }

    function u8b64(a) { let b = ''; for (let i = 0; i < a.length; i++) b += String.fromCharCode(a[i]); return btoa(b); }
    function b64u8(s) { const b = atob(s); const a = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; }

    function genKey() {
        const arr = new Uint8Array(16);
        crypto.getRandomValues(arr);
        return '0x' + Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    }

    function getKeys() {
        const k = [];
        $$('#keyLayers .key-layer-item input').forEach(i => {
            if (i.value.trim()) k.push(i.value.trim());
        });
        return k;
    }

    function mEncLegacy(d, keys) {
        let r = typeof d === 'string' ? new TextEncoder().encode(d) : d;
        for (const k of keys) { const c = new SC(BigInt(k)); r = c.enc(r); }
        return r;
    }

    function mDecLegacy(d, keys) {
        let r = d;
        for (let i = keys.length - 1; i >= 0; i--) { const c = new SC(BigInt(keys[i])); r = c.dec(r); }
        return r;
    }

    // --- WATERMARK & STEGANOGRAPHY ---
    function addWM(id) {
        const d = id.data;
        for (let i = 0; i < WM.length; i++) {
            for (let b = 0; b < 8; b++) {
                const p = i * 8 + b;
                if (p * 4 < d.length) d[p * 4] = (d[p * 4] & 0xFE) | ((WM[i] >> b) & 1);
            }
        }
        return id;
    }

    function hasWM(id) {
        const d = id.data;
        let m = 0;
        for (let i = 0; i < Math.min(WM.length, 10); i++) {
            let e = 0;
            for (let b = 0; b < 8; b++) {
                const p = i * 8 + b;
                if (p * 4 < d.length) e |= (d[p * 4] & 1) << b;
            }
            if (e === WM[i]) m++;
        }
        return m >= 5;
    }

    function embedTxt(cv, cx, txt, keys) {
        const id = cx.getImageData(0, 0, cv.width, cv.height);
        const d = id.data;
        const w = cv.width, h = cv.height;
        const enc = compactEncrypt(new TextEncoder().encode(txt), keys);

        const crc = SalistZip.crc32(enc) & 0xFFFF;
        const payload = new Uint8Array(8 + enc.length);
        payload[0] = 83; payload[1] = 76; payload[2] = 83; payload[3] = 84; // 'SLST'
        payload[4] = (enc.length >> 8) & 0xFF;
        payload[5] = enc.length & 0xFF;
        payload.set(enc, 6);
        payload[6 + enc.length] = (crc >> 8) & 0xFF;
        payload[7 + enc.length] = crc & 0xFF;

        const bits = [];
        for (let i = 0; i < payload.length; i++) {
            const b = payload[i];
            for (let j = 7; j >= 0; j--) bits.push((b >> j) & 1);
        }

        const cellW = 4, cellH = 4;
        const bitBlockW = cellW * 2, bitBlockH = cellH;
        const cols = Math.floor(w / bitBlockW);
        const rows = Math.floor(h / bitBlockH);
        const maxBits = cols * rows;

        if (bits.length > maxBits) {
            const full = "SL" + u8b64(enc) + "ED";
            const bin = [];
            for (let i = 0; i < full.length; i++) {
                const b = full.charCodeAt(i);
                for (let j = 7; j >= 0; j--) bin.push((b >> j) & 1);
            }
            for (let i = 0; i < bin.length && i * 4 < d.length; i++) {
                d[i * 4] = (d[i * 4] & 0xFE) | bin[i];
            }
            cx.putImageData(id, 0, 0);
            return;
        }

        const delta = 28;
        for (let bi = 0; bi < bits.length; bi++) {
            const bit = bits[bi];
            const col = bi % cols;
            const row = Math.floor(bi / cols);
            const bx = col * bitBlockW;
            const by = row * bitBlockH;

            for (let y = by; y < by + cellH; y++) {
                for (let x = bx; x < bx + cellW; x++) {
                    const pi = (y * w + x) * 4;
                    if (bit === 1) {
                        d[pi] = Math.min(255, d[pi] + delta);
                        d[pi + 1] = Math.min(255, d[pi + 1] + delta);
                        d[pi + 2] = Math.min(255, d[pi + 2] + delta);
                    } else {
                        d[pi] = Math.max(0, d[pi] - delta);
                        d[pi + 1] = Math.max(0, d[pi + 1] - delta);
                        d[pi + 2] = Math.max(0, d[pi + 2] - delta);
                    }
                }
                for (let x = bx + cellW; x < bx + bitBlockW; x++) {
                    const pi = (y * w + x) * 4;
                    if (bit === 1) {
                        d[pi] = Math.max(0, d[pi] - delta);
                        d[pi + 1] = Math.max(0, d[pi + 1] - delta);
                        d[pi + 2] = Math.max(0, d[pi + 2] - delta);
                    } else {
                        d[pi] = Math.min(255, d[pi] + delta);
                        d[pi + 1] = Math.min(255, d[pi + 1] + delta);
                        d[pi + 2] = Math.min(255, d[pi + 2] + delta);
                    }
                }
            }
        }
        cx.putImageData(id, 0, 0);
    }

    function extractTxt(cv, cx, keys) {
        const id = cx.getImageData(0, 0, cv.width, cv.height);
        const d = id.data;
        const w = cv.width, h = cv.height;

        const cellW = 4, cellH = 4;
        const bitBlockW = cellW * 2, bitBlockH = cellH;
        const cols = Math.floor(w / bitBlockW);
        const rows = Math.floor(h / bitBlockH);
        const totalBits = cols * rows;

        if (totalBits >= 64) {
            const bits = [];
            for (let bi = 0; bi < totalBits; bi++) {
                const col = bi % cols;
                const row = Math.floor(bi / cols);
                const bx = col * bitBlockW;
                const by = row * bitBlockH;

                let sum1 = 0, sum2 = 0;
                for (let y = by; y < by + cellH; y++) {
                    for (let x = bx; x < bx + cellW; x++) {
                        const pi = (y * w + x) * 4;
                        sum1 += (d[pi] + d[pi + 1] + d[pi + 2]);
                    }
                    for (let x = bx + cellW; x < bx + bitBlockW; x++) {
                        const pi = (y * w + x) * 4;
                        sum2 += (d[pi] + d[pi + 1] + d[pi + 2]);
                    }
                }
                bits.push(sum1 > sum2 ? 1 : 0);
            }

            const bytes = [];
            for (let i = 0; i + 8 <= bits.length; i += 8) {
                let b = 0;
                for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
                bytes.push(b);
            }

            if (bytes.length >= 8 && bytes[0] === 83 && bytes[1] === 76 && bytes[2] === 83 && bytes[3] === 84) {
                const encLen = (bytes[4] << 8) | bytes[5];
                if (encLen > 0 && bytes.length >= 8 + encLen) {
                    const encBytes = new Uint8Array(bytes.slice(6, 6 + encLen));
                    const storedCrc = (bytes[6 + encLen] << 8) | bytes[7 + encLen];
                    const calcCrc = SalistZip.crc32(encBytes) & 0xFFFF;
                    if (storedCrc === calcCrc) {
                        try {
                            const res = compactDecrypt(encBytes, keys);
                            return new TextDecoder().decode(res.data);
                        } catch (e) { }
                    }
                }
            }
        }

        const bin = [];
        for (let i = 0; i < Math.min(d.length / 4, 100000); i++) {
            bin.push(d[i * 4] & 1);
        }
        let txt = '';
        for (let i = 0; i + 8 <= bin.length; i += 8) {
            let b = 0;
            for (let j = 0; j < 8; j++) b = (b << 1) | bin[i + j];
            txt += String.fromCharCode(b);
            if (txt.endsWith("ED") && txt.includes("SL")) break;
        }
        const hi = txt.indexOf("SL");
        if (hi !== -1) {
            const ei = txt.indexOf("ED", hi);
            if (ei !== -1) {
                try {
                    const enc = b64u8(txt.substring(hi + 2, ei));
                    const res = compactDecrypt(enc, keys);
                    return new TextDecoder().decode(res.data);
                } catch (e) {
                    try {
                        const enc = b64u8(txt.substring(hi + 2, ei));
                        return new TextDecoder().decode(mDecLegacy(enc, keys));
                    } catch (e2) { return null; }
                }
            }
        }
        return null;
    }

    function procImg(cv, cx, keys, enc) {
        const id = cx.getImageData(0, 0, cv.width, cv.height);
        const d = id.data;
        let ck = 0n;
        for (const k of keys) {
            try { ck ^= BigInt(k); } catch (e) { }
        }
        const c = new SC(ck || 123456789n);
        const ks = c.prga(d.length);
        for (let i = 0; i < d.length; i += 4) {
            d[i] ^= ks[i];
            d[i + 1] ^= ks[i + 1];
            d[i + 2] ^= ks[i + 2];
        }
        if (enc) addWM(id);
        cx.putImageData(id, 0, 0);
    }

    // --- CLIPBOARD & FILE HELPERS ---
    async function safeCopy(text) {
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(text);
                return true;
            }
        } catch (e) { }
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.cssText = 'position:fixed;left:0;top:0;width:1px;height:1px;opacity:0.01';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        let ok = false;
        try { ok = document.execCommand('copy'); } catch (e) { }
        document.body.removeChild(ta);
        return ok;
    }

    async function safeCopyImg(src) {
        try {
            if (!isTg && navigator.clipboard && window.ClipboardItem) {
                const r = await fetch(src);
                const b = await r.blob();
                await navigator.clipboard.write([new ClipboardItem({ [b.type]: b })]);
                return true;
            }
        } catch (e) { }
        return false;
    }

    async function safePaste() {
        try {
            if (!isTg && navigator.clipboard && navigator.clipboard.readText) {
                const t2 = await navigator.clipboard.readText();
                if (t2) return { type: 'text', data: t2 };
            }
        } catch (e) { }
        try {
            if (!isTg && navigator.clipboard && navigator.clipboard.read) {
                const items = await navigator.clipboard.read();
                for (const item of items) {
                    if (item.types.includes('text/plain')) {
                        const b = await item.getType('text/plain');
                        return { type: 'text', data: await b.text() };
                    }
                    for (const type of item.types) {
                        if (type.startsWith('image/')) {
                            const b = await item.getType(type);
                            return { type: 'image', data: b };
                        }
                    }
                }
            }
        } catch (e) { }
        return null;
    }

    async function safePasteImg(pid, cid, cb, fallbackInputId) {
        try {
            if (!isTg && navigator.clipboard && navigator.clipboard.read) {
                const items = await navigator.clipboard.read();
                for (const item of items) {
                    for (const type of item.types) {
                        if (type.startsWith('image/')) {
                            const blob = await item.getType(type);
                            if (blob.size > MAX_FILE) {
                                toast('File too large', 'error');
                                return;
                            }
                            const r = new FileReader();
                            r.onload = e => loadImg(e.target.result, pid, cid, cb);
                            r.readAsDataURL(blob);
                            return;
                        }
                    }
                }
            }
        } catch (e) { }
        if (fallbackInputId) { $(fallbackInputId).click(); return; }
        toast('No image in clipboard', 'error');
    }

    function safeDl(blobOrUrl, filename) {
        let url = typeof blobOrUrl === 'string' ? blobOrUrl : URL.createObjectURL(blobOrUrl);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
            document.body.removeChild(a);
            if (typeof blobOrUrl !== 'string') URL.revokeObjectURL(url);
        }, 3000);
    }

    // --- TOAST NOTIFICATIONS ---
    function toast(msg, type = 'info') {
        const c = $('toastContainer');
        if (!c) return;
        const d = document.createElement('div');
        d.className = 'toast toast-' + type;
        const icons = {
            success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
            error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
            info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
        };
        d.innerHTML = (icons[type] || icons.info) + '<span>' + msg + '</span>';
        c.appendChild(d);
        setTimeout(() => {
            d.classList.add('removing');
            setTimeout(() => d.remove(), 160);
        }, 2400);
    }

    // --- BUTTON SPINNER LOADING (NO SCREEN FLICKER / RELOAD) ---
    function setButtonBusy(btn, isBusy) {
        if (!btn) return;
        if (isBusy) {
            btn._origHtml = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="btn-spinner"></span>';
        } else {
            if (btn._origHtml) btn.innerHTML = btn._origHtml;
            btn.disabled = false;
        }
    }

    // --- THEME ---
    function setTheme(th) {
        document.documentElement.setAttribute('data-theme', th);
        s('theme', th);
        const icon = th === 'dark'
            ? '<svg id="themeIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>'
            : '<svg id="themeIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
        const currentIcon = $('themeIcon');
        if (currentIcon) currentIcon.outerHTML = icon;
    }

    // --- GLISSE TAB BAR CONTROLLER ---
    function switchTab(tab, tabIndex) {
        const tabBar = document.querySelector('.lg-tab-bar');
        const tabs = $$('.lg-tab');
        const contents = $$('.tab-content');

        tabs.forEach((t2, i) => {
            const isMatch = (t2.dataset.tab === tab);
            if (isMatch) {
                t2.setAttribute('data-selected', '');
                t2.setAttribute('aria-selected', 'true');
                if (tabBar) tabBar.style.setProperty('--lg-index', i);
            } else {
                t2.removeAttribute('data-selected');
                t2.setAttribute('aria-selected', 'false');
            }
        });

        contents.forEach(c => c.classList.toggle('active', c.dataset.content === tab));
        mode = tab;
        resetResult();

        // If on Tools tab: Hide bottom key layers section and encrypt/decrypt buttons!
        const isTools = (tab === 'tools');
        const keySection = $('keyLayersSection');
        const actionSection = $('mainActionsSection');
        if (keySection) keySection.style.display = isTools ? 'none' : '';
        if (actionSection) actionSection.style.display = isTools ? 'none' : '';

        if (isTools) {
            generatePassword();
            const inp = $('inputText') ? $('inputText').value : '';
            if (inp) {
                if ($('hashInput')) $('hashInput').value = inp;
                updateHashes(inp);
            }
        }
    }

    // --- KEY LAYERS MANAGEMENT ---
    function updateKeyBadge() {
        const n = $$('#keyLayers .key-layer-item').length;
        const b = $('keyCountBadge');
        if (b) b.textContent = `${n} Layer${n > 1 ? 's' : ''}`;
    }

    function updateNums() {
        $$('#keyLayers .key-layer-item').forEach((l, i) => {
            l.querySelector('.key-index').textContent = i + 1;
            l.dataset.layer = i + 1;
        });
        updateKeyBadge();
    }

    function makeKeyLayer(n) {
        const d = document.createElement('div');
        d.className = 'key-layer-item';
        d.dataset.layer = n;
        d.innerHTML = `
            <span class="key-index">${n}</span>
            <input type="password" class="key-input" placeholder="Enter password or key...">
            <div class="key-btn-group">
                <button type="button" class="key-action-btn toggle-vis" title="Show/Hide">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                    </svg>
                </button>
                <button type="button" class="key-action-btn copy-key" title="Copy">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                    </svg>
                </button>
                <button type="button" class="key-action-btn remove-key-btn" title="Remove">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                </button>
            </div>
        `;
        return d;
    }

    // --- RESULT & WARNINGS ---
    function resetResult() {
        const rs = $('resultSection');
        if (rs) rs.classList.remove('show');
        if ($('outputText')) {
            $('outputText').value = '';
            $('outputText').style.display = 'block';
        }
        if ($('resultImage')) {
            $('resultImage').classList.remove('show');
            $('resultImage').src = '';
        }
        if ($('downloadBtn')) $('downloadBtn').style.display = 'none';
        if ($('qrBtn')) $('qrBtn').style.display = 'none';
        if ($('qrContainer')) $('qrContainer').classList.remove('show');
        if ($('verifiedBadge')) $('verifiedBadge').classList.remove('show');
        encryptedFileBlob = null;
        decryptedFileBlob = null;
        hideWarnings();
    }

    function hideWarnings() { $$('.warning-bar').forEach(w => w.classList.remove('show')); }
    function showWarning(id) { const el = $(id); if (el) el.classList.add('show'); }

    // --- STEGO CAPACITY ---
    function updateCap() {
        const txt = $('secretText') ? $('secretText').value : '';
        const info = $('stegoInfo');
        const fill = $('capacityFill');
        const ct = $('capacityText');
        if (!stegoImgData) {
            if (info) info.classList.remove('show');
            return;
        }
        if (info) info.classList.add('show');
        const mx = Math.floor(stegoImgData.w * stegoImgData.h * 3 / 12);
        const pct = mx > 0 ? (txt.length / mx) * 100 : 0;
        if (fill) {
            fill.style.width = Math.min(pct, 100) + '%';
            fill.className = 'progress-fill ' + (pct > 90 ? 'danger' : pct > 70 ? 'warn' : '');
        }
        if (ct) ct.textContent = `${txt.length} / ${mx} (${pct.toFixed(1)}%)`;
    }

    function loadImg(src, pid, cid, cb, dropZoneId) {
        const img = new Image();
        img.crossOrigin = 'anonymous';
        img.onload = () => {
            const previewEl = $(pid);
            if (previewEl) previewEl.src = src;
            const containerEl = $(cid);
            if (containerEl) containerEl.classList.add('show');
            // Hide the dropzone card on selection
            if (dropZoneId && $(dropZoneId)) $(dropZoneId).style.display = 'none';
            cb(img);
            toast('Image loaded successfully', 'success');
        };
        img.onerror = () => toast('Image load error', 'error');
        img.src = src;
    }

    function handleFile(file, pid, cid, cb, dropZoneId) {
        if (!file) return;
        if (file.size > MAX_FILE) { toast('File exceeds 50MB limit', 'error'); return; }
        const r = new FileReader();
        r.onload = e => loadImg(e.target.result, pid, cid, cb, dropZoneId);
        r.readAsDataURL(file);
    }

    // --- QR CODE GENERATION & SCANNING ---
    function genQRInto(data, targetContainerId, targetCodeId) {
        if (!data || !data.trim()) {
            toast('Enter text to generate QR', 'error');
            return false;
        }
        try {
            if (typeof qrcode === 'undefined') {
                toast('QR generator unavailable', 'error');
                return false;
            }
            const qr = qrcode(0, 'M');
            qr.addData(data.trim());
            qr.make();
            const targetCode = $(targetCodeId);
            const targetContainer = $(targetContainerId);
            if (targetCode && targetContainer) {
                targetCode.innerHTML = qr.createSvgTag({ cellSize: 6, margin: 4 });
                targetContainer.classList.add('show');
                toast('QR Code generated', 'success');
                return true;
            }
        } catch (e) {
            toast('QR error: ' + (e.message || 'overflow'), 'error');
        }
        return false;
    }

    async function scanQR(src) {
        return new Promise(res => {
            const img = new Image();
            img.crossOrigin = 'anonymous';
            img.onload = () => {
                const c = document.createElement('canvas');
                c.width = img.width;
                c.height = img.height;
                const cx = c.getContext('2d');
                cx.drawImage(img, 0, 0);
                const id = cx.getImageData(0, 0, c.width, c.height);
                if (typeof jsQR !== 'undefined') {
                    const code = jsQR(id.data, id.width, id.height);
                    res(code ? code.data : null);
                } else {
                    res(null);
                }
            };
            img.onerror = () => res(null);
            img.src = src;
        });
    }

    // --- GLISSE SLIDER PROGRESS (ZERO-LATENCY, INSTANT SYNC) ---
    function updateSliderProgress(slider) {
        if (!slider) return;
        const min = parseFloat(slider.min) || 6;
        const max = parseFloat(slider.max) || 64;
        const val = parseFloat(slider.value) || min;
        const progress = max > min ? Math.min(1, Math.max(0, (val - min) / (max - min))) : 0;
        const wrap = slider.closest('.lg-slider');
        if (wrap) wrap.style.setProperty('--lg-progress', progress);
        if ($('passLengthVal')) $('passLengthVal').textContent = val;
    }

    // --- PASSWORD GENERATOR & ENTROPY ---
    function calculateEntropy(pass) {
        if (!pass) return { bits: 0, pct: 0 };
        let pool = 0;
        if (/[a-z]/.test(pass)) pool += 26;
        if (/[A-Z]/.test(pass)) pool += 26;
        if (/[0-9]/.test(pass)) pool += 10;
        if (/[^a-zA-Z0-9]/.test(pass)) pool += 33;
        if (pool === 0) pool = 1;
        const bits = Math.floor(pass.length * (Math.log(pool) / Math.log(2)));
        const pct = Math.min(Math.floor((bits / 128) * 100), 100);
        return { bits, pct };
    }

    function isSwitchChecked(id) {
        const el = $(id);
        return el ? el.getAttribute('aria-checked') === 'true' : false;
    }

    function generatePassword() {
        const slider = $('passLengthSlider');
        if (!slider) return;
        const len = parseInt(slider.value, 10);
        updateSliderProgress(slider);

        let charset = "";
        if (isSwitchChecked('optUpper')) charset += "ABCDEFGHJKLMNPQRSTUVWXYZ";
        if (isSwitchChecked('optLower')) charset += "abcdefghjkmnpqrstuvwxyz";
        if (isSwitchChecked('optNumbers')) charset += "23456789";
        if (isSwitchChecked('optSymbols')) charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";
        if (!charset) charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*";

        const values = new Uint32Array(len);
        crypto.getRandomValues(values);
        let pass = "";
        for (let i = 0; i < len; i++) {
            pass += charset[values[i] % charset.length];
        }

        if ($('genPassOutput')) $('genPassOutput').value = pass;
        const ent = calculateEntropy(pass);
        if ($('entropyBadge')) $('entropyBadge').textContent = ent.bits + " bits";
        if ($('entropyFill')) {
            $('entropyFill').style.width = ent.pct + "%";
            $('entropyFill').style.background = ent.pct > 75 ? "var(--status-success)" : ent.pct > 40 ? "var(--status-warning)" : "var(--status-danger)";
        }
    }

    // --- HASH & CHECKSUM SUITE ---
    async function updateHashes(textOrBuffer) {
        try {
            let dataBytes;
            if (typeof textOrBuffer === 'string') {
                dataBytes = new TextEncoder().encode(textOrBuffer);
                if (typeof md5 !== 'undefined' && $('hashMd5')) $('hashMd5').textContent = md5(textOrBuffer);
            } else {
                dataBytes = new Uint8Array(textOrBuffer);
                if (typeof md5 !== 'undefined' && $('hashMd5')) $('hashMd5').textContent = md5(dataBytes);
            }

            if (dataBytes.length === 0) {
                if ($('hashMd5')) $('hashMd5').textContent = '-';
                if ($('hashSha1')) $('hashSha1').textContent = '-';
                if ($('hashSha256')) $('hashSha256').textContent = '-';
                if ($('hashSha512')) $('hashSha512').textContent = '-';
                return;
            }

            const sha1Buf = await crypto.subtle.digest("SHA-1", dataBytes);
            if ($('hashSha1')) $('hashSha1').textContent = Array.from(new Uint8Array(sha1Buf)).map(b => b.toString(16).padStart(2, '0')).join('');

            const sha256Buf = await crypto.subtle.digest("SHA-256", dataBytes);
            if ($('hashSha256')) $('hashSha256').textContent = Array.from(new Uint8Array(sha256Buf)).map(b => b.toString(16).padStart(2, '0')).join('');

            const sha512Buf = await crypto.subtle.digest("SHA-512", dataBytes);
            if ($('hashSha512')) $('hashSha512').textContent = Array.from(new Uint8Array(sha512Buf)).map(b => b.toString(16).padStart(2, '0')).join('');
        } catch (e) { }
    }

    // --- SMART AUTO-DETECTION ---
    function checkSmartDetection(str) {
        const banner = $('smartBanner');
        const badge = $('smartBadge');
        const text = $('smartText');
        const btn = $('smartActionBtn');
        if (!banner || !badge || !text || !btn) return;

        if (!str || str.length < 8) {
            banner.classList.remove('show');
            return;
        }

        const trimmed = str.trim();
        if (trimmed.startsWith('S:')) {
            badge.textContent = "COMPACT CIPHER";
            text.textContent = "Encrypted Stream Payload";
            btn.textContent = "Decrypt";
            btn.onclick = () => { switchTab('text'); $('decryptBtn').click(); };
            banner.classList.add('show');
        } else if (trimmed.startsWith(MARKER_V4 + ':')) {
            badge.textContent = "AES-256-GCM";
            text.textContent = "Cascaded Authenticated Payload";
            btn.textContent = "Decrypt";
            btn.onclick = () => { switchTab('text'); $('decryptBtn').click(); };
            banner.classList.add('show');
        } else if (trimmed.startsWith(MARKER + ':')) {
            badge.textContent = "LEGACY CIPHER";
            text.textContent = "Encrypted Stream Payload";
            btn.textContent = "Decrypt Legacy";
            btn.onclick = () => { switchTab('text'); $('decryptBtn').click(); };
            banner.classList.add('show');
        } else if (/^[a-fA-F0-9]{32,128}$/.test(trimmed)) {
            badge.textContent = "HASH CHECKSUM";
            text.textContent = "Cryptographic Digest (" + trimmed.length * 4 + "-bit)";
            btn.textContent = "View Tools";
            btn.onclick = () => switchTab('tools');
            banner.classList.add('show');
        } else {
            banner.classList.remove('show');
        }
    }

    function renderSelectedFiles() {
        const list = $('selectedFileList');
        const box = $('fileSelectionBox');
        const drop = $('fileDropZone');
        if (!list) return;

        if (selectedFiles.length === 0) {
            if (box) box.style.display = 'none';
            if (drop) drop.style.display = '';
            list.innerHTML = '';
            return;
        }

        if (drop) drop.style.display = 'none';
        if (box) box.style.display = 'flex';
        if ($('fileCountLabel')) $('fileCountLabel').textContent = `Selected Files (${selectedFiles.length})`;

        list.innerHTML = '';
        selectedFiles.forEach((f) => {
            const row = document.createElement('div');
            row.className = 'file-item';
            row.innerHTML = `
                <div class="file-item-left">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                        <polyline points="14 2 14 8 20 8"/>
                    </svg>
                    <span class="file-item-name">${f.name}</span>
                </div>
                <span class="file-item-size">${(f.size / 1024).toFixed(1)} KB</span>
            `;
            list.appendChild(row);
        });
    }

    // --- INITIALIZATION ---
    document.addEventListener('DOMContentLoaded', () => {
        const savedTheme = s('theme') || 'dark';
        setTheme(savedTheme);

        if ($('themeToggle')) {
            $('themeToggle').addEventListener('click', () => {
                const cur = document.documentElement.getAttribute('data-theme');
                setTheme(cur === 'dark' ? 'light' : 'dark');
            });
        }

        // Glisse TabBar listener
        $$('.lg-tab').forEach((tab, idx) => {
            tab.addEventListener('click', () => switchTab(tab.dataset.tab, idx));
        });

        // Glisse Switches setup
        $$('.lg-switch').forEach(sw => {
            sw.addEventListener('click', () => {
                const current = sw.getAttribute('aria-checked') === 'true';
                sw.setAttribute('aria-checked', !current);
                generatePassword();
            });
        });

        // Glisse Slider setup (instant zero lag)
        const slider = $('passLengthSlider');
        if (slider) {
            updateSliderProgress(slider);
            slider.addEventListener('input', () => {
                updateSliderProgress(slider);
                generatePassword();
            });
        }

        // Key Layers
        if ($('addKeyBtn')) {
            $('addKeyBtn').addEventListener('click', () => {
                const layers = $('keyLayers');
                if (layers.children.length >= 5) return;
                const n = layers.children.length + 1;
                layers.appendChild(makeKeyLayer(n));
                updateNums();
            });
        }
        if ($('generateKeyBtn')) {
            $('generateKeyBtn').addEventListener('click', () => {
                $$('#keyLayers .key-layer-item input').forEach(inp => inp.value = genKey());
                toast('Secure keys generated', 'success');
            });
        }

        if ($('keyLayers')) {
            $('keyLayers').addEventListener('click', e => {
                const togBtn = e.target.closest('.toggle-vis');
                if (togBtn) {
                    const inp = togBtn.closest('.key-layer-item').querySelector('input');
                    inp.type = inp.type === 'password' ? 'text' : 'password';
                    const isVis = inp.type === 'text';
                    togBtn.innerHTML = isVis
                        ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'
                        : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
                    return;
                }
                const cpBtn = e.target.closest('.copy-key');
                if (cpBtn) {
                    const inp = cpBtn.closest('.key-layer-item').querySelector('input');
                    if (inp.value) {
                        safeCopy(inp.value).then(ok => toast(ok ? 'Copied to clipboard' : 'Copy failed', ok ? 'success' : 'error'));
                    } else toast('Key is empty', 'error');
                    return;
                }
                const rmBtn = e.target.closest('.remove-key-btn');
                if (rmBtn) {
                    const layer = rmBtn.closest('.key-layer-item');
                    if ($$('#keyLayers .key-layer-item').length <= 1) return;
                    layer.style.opacity = '0';
                    layer.style.transform = 'scale(0.9)';
                    setTimeout(() => { layer.remove(); updateNums(); }, 140);
                    return;
                }
            });
        }

        // Text Tab Handlers
        if ($('inputText')) $('inputText').addEventListener('input', e => checkSmartDetection(e.target.value));
        if ($('clearTextBtn')) {
            $('clearTextBtn').addEventListener('click', () => {
                $('inputText').value = '';
                checkSmartDetection('');
                if ($('textQrContainer')) $('textQrContainer').classList.remove('show');
            });
        }
        if ($('pasteTextBtn')) {
            $('pasteTextBtn').addEventListener('click', async () => {
                const r = await safePaste();
                if (!r) return;
                if (r.type === 'text') {
                    $('inputText').value = r.data;
                    checkSmartDetection(r.data);
                    toast('Pasted from clipboard', 'success');
                    return;
                }
                if (r.type === 'image') {
                    const reader = new FileReader();
                    reader.onload = async ev => {
                        const qr = await scanQR(ev.target.result);
                        if (qr) {
                            $('inputText').value = qr.replace(/^(SALISTv4|SALIST):/, '');
                            checkSmartDetection(qr);
                            toast('QR code scanned', 'success');
                        } else toast('Invalid QR code', 'error');
                    };
                    reader.readAsDataURL(r.data);
                }
            });
        }

        // QR Code in Text Tab
        if ($('genTextQrBtn')) {
            $('genTextQrBtn').addEventListener('click', () => {
                const txt = $('inputText').value;
                genQRInto(txt, 'textQrContainer', 'textQrCode');
            });
        }
        if ($('closeTextQrBtn')) {
            $('closeTextQrBtn').addEventListener('click', () => {
                if ($('textQrContainer')) $('textQrContainer').classList.remove('show');
            });
        }
        if ($('scanQrBtn')) $('scanQrBtn').addEventListener('click', () => $('qrFileInput').click());
        if ($('qrFileInput')) {
            $('qrFileInput').addEventListener('change', async e => {
                const f = e.target.files[0];
                if (!f) return;
                const r = new FileReader();
                r.onload = async ev => {
                    const qr = await scanQR(ev.target.result);
                    if (qr) {
                        $('inputText').value = qr;
                        checkSmartDetection(qr);
                        toast('QR code scanned', 'success');
                    } else toast('Invalid QR code', 'error');
                };
                r.readAsDataURL(f);
                e.target.value = '';
            });
        }

        // Files Tab Handlers (Clicking dropzone anywhere opens picker; hide card on select)
        const fileDrop = $('fileDropZone');
        if (fileDrop) {
            fileDrop.addEventListener('click', (e) => {
                if ($('universalFileInput')) $('universalFileInput').click();
            });
            ['dragenter', 'dragover'].forEach(ev => fileDrop.addEventListener(ev, e => { e.preventDefault(); fileDrop.classList.add('dragover'); }));
            ['dragleave', 'drop'].forEach(ev => fileDrop.addEventListener(ev, e => { e.preventDefault(); fileDrop.classList.remove('dragover'); }));
            fileDrop.addEventListener('drop', e => {
                e.preventDefault();
                if (e.dataTransfer.files.length) {
                    selectedFiles = Array.from(e.dataTransfer.files);
                    renderSelectedFiles();
                }
            });
        }
        if ($('uploadFileBtn')) {
            $('uploadFileBtn').addEventListener('click', (e) => {
                e.stopPropagation();
                $('universalFileInput').click();
            });
        }
        if ($('createZipBtn')) {
            $('createZipBtn').addEventListener('click', (e) => {
                e.stopPropagation();
                $('universalFileInput').click();
            });
        }
        if ($('universalFileInput')) {
            $('universalFileInput').addEventListener('change', e => {
                selectedFiles = Array.from(e.target.files);
                renderSelectedFiles();
            });
        }
        if ($('clearFilesBtn')) {
            $('clearFilesBtn').addEventListener('click', () => {
                selectedFiles = [];
                renderSelectedFiles();
                if ($('universalFileInput')) $('universalFileInput').value = '';
            });
        }

        // Image Tab Handlers (Click dropzone anywhere opens picker; buttons centered; hide card on select)
        const imgDrop = $('imageDropZone');
        if (imgDrop) {
            imgDrop.addEventListener('click', () => {
                if ($('imageFileInput')) $('imageFileInput').click();
            });
            ['dragenter', 'dragover'].forEach(e => imgDrop.addEventListener(e, ev => { ev.preventDefault(); imgDrop.classList.add('dragover'); }));
            ['dragleave', 'drop'].forEach(e => imgDrop.addEventListener(e, ev => { ev.preventDefault(); imgDrop.classList.remove('dragover'); }));
            imgDrop.addEventListener('drop', e => {
                e.preventDefault();
                const f = e.dataTransfer.files[0];
                if (f && f.type.startsWith('image/')) handleFile(f, 'imagePreviewImg', 'imagePreview', img => { imgData = { img, w: img.width, h: img.height }; }, 'imageDropZone');
            });
        }
        if ($('uploadImageBtn')) {
            $('uploadImageBtn').addEventListener('click', (e) => {
                e.stopPropagation();
                $('imageFileInput').click();
            });
        }
        if ($('pasteImageBtn')) {
            $('pasteImageBtn').addEventListener('click', (e) => {
                e.stopPropagation();
                safePasteImg('imagePreviewImg', 'imagePreview', img => { imgData = { img, w: img.width, h: img.height }; if (imgDrop) imgDrop.style.display = 'none'; }, 'imageFileInput');
            });
        }
        if ($('imageFileInput')) {
            $('imageFileInput').addEventListener('change', e => {
                handleFile(e.target.files[0], 'imagePreviewImg', 'imagePreview', img => { imgData = { img, w: img.width, h: img.height }; }, 'imageDropZone');
                e.target.value = '';
            });
        }
        if ($('removeImagePreview')) {
            $('removeImagePreview').addEventListener('click', () => {
                $('imagePreview').classList.remove('show');
                if (imgDrop) imgDrop.style.display = '';
                imgData = null;
            });
        }

        // Stego Tab Handlers (Click dropzone anywhere opens picker; buttons centered; hide card on select)
        const stegoDrop = $('stegoDropZone');
        if (stegoDrop) {
            stegoDrop.addEventListener('click', () => {
                if ($('stegoFileInput')) $('stegoFileInput').click();
            });
            ['dragenter', 'dragover'].forEach(e => stegoDrop.addEventListener(e, ev => { ev.preventDefault(); stegoDrop.classList.add('dragover'); }));
            ['dragleave', 'drop'].forEach(e => stegoDrop.addEventListener(e, ev => { ev.preventDefault(); stegoDrop.classList.remove('dragover'); }));
            stegoDrop.addEventListener('drop', e => {
                e.preventDefault();
                const f = e.dataTransfer.files[0];
                if (f && f.type.startsWith('image/')) handleFile(f, 'stegoPreviewImg', 'stegoPreview', img => { stegoImgData = { img, w: img.width, h: img.height }; updateCap(); }, 'stegoDropZone');
            });
        }
        if ($('uploadStegoBtn')) {
            $('uploadStegoBtn').addEventListener('click', (e) => {
                e.stopPropagation();
                $('stegoFileInput').click();
            });
        }
        if ($('pasteStegoBtn')) {
            $('pasteStegoBtn').addEventListener('click', (e) => {
                e.stopPropagation();
                safePasteImg('stegoPreviewImg', 'stegoPreview', img => { stegoImgData = { img, w: img.width, h: img.height }; updateCap(); if (stegoDrop) stegoDrop.style.display = 'none'; }, 'stegoFileInput');
            });
        }
        if ($('stegoFileInput')) {
            $('stegoFileInput').addEventListener('change', e => {
                handleFile(e.target.files[0], 'stegoPreviewImg', 'stegoPreview', img => { stegoImgData = { img, w: img.width, h: img.height }; updateCap(); }, 'stegoDropZone');
                e.target.value = '';
            });
        }
        if ($('removeStegoPreview')) {
            $('removeStegoPreview').addEventListener('click', () => {
                $('stegoPreview').classList.remove('show');
                if (stegoDrop) stegoDrop.style.display = '';
                stegoImgData = null;
                if ($('stegoInfo')) $('stegoInfo').classList.remove('show');
            });
        }
        if ($('secretText')) $('secretText').addEventListener('input', updateCap);

        // Tools Tab Event Handlers
        if ($('reGenPassBtn')) $('reGenPassBtn').addEventListener('click', generatePassword);
        if ($('copyGenPassBtn')) {
            $('copyGenPassBtn').addEventListener('click', () => {
                const pass = $('genPassOutput').value;
                if (pass) safeCopy(pass).then(ok => toast(ok ? 'Password copied' : 'Failed', ok ? 'success' : 'error'));
            });
        }
        if ($('hashInput')) {
            $('hashInput').addEventListener('input', e => updateHashes(e.target.value));
        }
        $$('.copy-hash-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const targetId = btn.dataset.target;
                const text = $(targetId) ? $(targetId).textContent : '';
                if (text && text !== '-') safeCopy(text).then(ok => toast(ok ? 'Hash copied' : 'Failed', ok ? 'success' : 'error'));
            });
        });

        // PRIMARY ENCRYPT ACTION (With inline button spinner, no screen flash)
        if ($('encryptBtn')) {
            $('encryptBtn').addEventListener('click', async () => {
                const btn = $('encryptBtn');
                const keys = getKeys();
                if (!keys.length) { toast('Enter at least one key', 'error'); return; }
                resetResult();
                setButtonBusy(btn, true);

                setTimeout(async () => {
                    try {
                        if (mode === 'text') {
                            const txt = $('inputText').value;
                            if (!txt) { setButtonBusy(btn, false); return; }
                            const plainBytes = new TextEncoder().encode(txt);
                            const encBytes = compactEncrypt(plainBytes, keys);
                            const encoded = u8b64(encBytes);
                            $('outputText').value = 'S:' + encoded;
                            $('verifiedBadge').classList.add('show');
                            $('qrBtn').style.display = '';
                            $('qrBtn').onclick = () => genQRInto('S:' + encoded, 'qrContainer', 'qrCode');
                            $('resultSection').classList.add('show');
                            toast('Encrypted successfully', 'success');
                        } else if (mode === 'files') {
                            if (!selectedFiles.length) { toast('No files selected', 'error'); setButtonBusy(btn, false); return; }
                            let filePayload;
                            let outName = "encrypted_archive.salist";

                            if (selectedFiles.length === 1 && !selectedFiles[0].name.endsWith('.salist')) {
                                const f = selectedFiles[0];
                                const buf = await f.arrayBuffer();
                                const meta = JSON.stringify({ name: f.name, type: f.type, size: f.size });
                                const metaBytes = new TextEncoder().encode(meta);
                                const combined = new Uint8Array(4 + metaBytes.length + buf.byteLength);
                                new DataView(combined.buffer).setUint32(0, metaBytes.length, true);
                                combined.set(metaBytes, 4);
                                combined.set(new Uint8Array(buf), 4 + metaBytes.length);
                                filePayload = combined;
                                outName = f.name + ".salist";
                            } else {
                                const zipEntries = {};
                                for (const f of selectedFiles) {
                                    const buf = await f.arrayBuffer();
                                    zipEntries[f.name] = new Uint8Array(buf);
                                }
                                const zipBytes = SalistZip.zipSync(zipEntries);
                                const meta = JSON.stringify({ name: "archive.zip", type: "application/zip", isZip: true });
                                const metaBytes = new TextEncoder().encode(meta);
                                const combined = new Uint8Array(4 + metaBytes.length + zipBytes.length);
                                new DataView(combined.buffer).setUint32(0, metaBytes.length, true);
                                combined.set(metaBytes, 4);
                                combined.set(zipBytes, 4 + metaBytes.length);
                                filePayload = combined;
                            }

                            const encBytes = await multiLayerV4Encrypt(filePayload, keys);
                            encryptedFileBlob = new Blob([encBytes], { type: "application/octet-stream" });
                            decryptedFileName = outName;
                            $('outputText').value = `[ENCRYPTED CONTAINER: ${outName} (${(encBytes.length / 1024).toFixed(1)} KB)]\nAES-256-GCM Multi-Layer Authenticated Container Ready.`;
                            $('downloadBtn').style.display = '';
                            $('verifiedBadge').classList.add('show');
                            $('resultSection').classList.add('show');
                            toast('Files encrypted into secure container', 'success');
                        } else if (mode === 'image') {
                            if (!imgData) { toast('Select an image first', 'error'); setButtonBusy(btn, false); return; }
                            const cv = $('workCanvas');
                            const cx = cv.getContext('2d', { willReadFrequently: true });
                            cv.width = imgData.w;
                            cv.height = imgData.h;
                            cx.drawImage(imgData.img, 0, 0);
                            procImg(cv, cx, keys, true);
                            const url = cv.toDataURL('image/png');
                            $('resultImage').src = url;
                            $('resultImage').classList.add('show');
                            $('outputText').style.display = 'none';
                            $('downloadBtn').style.display = '';
                            $('resultSection').classList.add('show');
                            toast('Image scrambled with security watermark', 'success');
                        } else if (mode === 'stego') {
                            if (!stegoImgData) { toast('Select carrier image first', 'error'); setButtonBusy(btn, false); return; }
                            const txt = $('secretText').value;
                            if (!txt) { toast('Enter secret text to hide', 'error'); setButtonBusy(btn, false); return; }
                            const cv = $('workCanvas');
                            const cx = cv.getContext('2d', { willReadFrequently: true });
                            cv.width = stegoImgData.w;
                            cv.height = stegoImgData.h;
                            cx.drawImage(stegoImgData.img, 0, 0);
                            try {
                                embedTxt(cv, cx, txt, keys);
                                const url = cv.toDataURL('image/png');
                                $('resultImage').src = url;
                                $('resultImage').classList.add('show');
                                $('outputText').style.display = 'none';
                                $('downloadBtn').style.display = '';
                                $('resultSection').classList.add('show');
                                toast('Text hidden inside carrier image', 'success');
                            } catch (er) {
                                toast('Carrier image is too small for this message', 'error');
                            }
                        }
                    } catch (er) {
                        toast('Encryption error', 'error');
                    }
                    setButtonBusy(btn, false);
                }, 40);
            });
        }

        // PRIMARY DECRYPT ACTION (With inline button spinner, no screen flash)
        if ($('decryptBtn')) {
            $('decryptBtn').addEventListener('click', async () => {
                const btn = $('decryptBtn');
                const keys = getKeys();
                if (!keys.length) { toast('Enter at least one key', 'error'); return; }
                resetResult();
                setButtonBusy(btn, true);

                setTimeout(async () => {
                    try {
                        if (mode === 'text') {
                            let enc = $('inputText').value.trim();
                            if (!enc) { setButtonBusy(btn, false); return; }

                            if (enc.startsWith('S:')) {
                                enc = enc.substring(2);
                                const raw = b64u8(enc);
                                const res = compactDecrypt(raw, keys);
                                $('outputText').value = new TextDecoder().decode(res.data);
                                if (res.verified) $('verifiedBadge').classList.add('show');
                                $('resultSection').classList.add('show');
                                toast('Decrypted successfully', 'success');
                            } else if (enc.startsWith(MARKER_V4 + ':')) {
                                enc = enc.substring(MARKER_V4.length + 1);
                                const data = b64u8(enc);
                                const dec = await multiLayerV4Decrypt(data, keys);
                                $('outputText').value = new TextDecoder().decode(dec);
                                $('verifiedBadge').classList.add('show');
                                $('resultSection').classList.add('show');
                                toast('Decrypted successfully', 'success');
                            } else if (enc.startsWith(MARKER + ':')) {
                                enc = enc.substring(MARKER.length + 1);
                                const data = b64u8(enc);
                                const dec = mDecLegacy(data, keys);
                                $('outputText').value = new TextDecoder().decode(dec);
                                $('verifiedBadge').classList.add('show');
                                $('resultSection').classList.add('show');
                                toast('Decrypted successfully', 'success');
                            } else {
                                try {
                                    const raw = b64u8(enc);
                                    const res = compactDecrypt(raw, keys);
                                    $('outputText').value = new TextDecoder().decode(res.data);
                                    if (res.verified) $('verifiedBadge').classList.add('show');
                                    $('resultSection').classList.add('show');
                                    toast('Decrypted successfully', 'success');
                                } catch (e1) {
                                    try {
                                        const data = b64u8(enc);
                                        const dec = await multiLayerV4Decrypt(data, keys);
                                        $('outputText').value = new TextDecoder().decode(dec);
                                        $('verifiedBadge').classList.add('show');
                                        $('resultSection').classList.add('show');
                                        toast('Decrypted successfully', 'success');
                                    } catch (e2) {
                                        const data = b64u8(enc);
                                        const dec = mDecLegacy(data, keys);
                                        $('outputText').value = new TextDecoder().decode(dec);
                                        $('resultSection').classList.add('show');
                                        showWarning('textWarning');
                                    }
                                }
                            }
                        } else if (mode === 'files') {
                            if (!selectedFiles.length) { toast('No files selected', 'error'); setButtonBusy(btn, false); return; }
                            const file = selectedFiles[0];
                            const fileBuf = await file.arrayBuffer();
                            const cipherBytes = new Uint8Array(fileBuf);
                            const decBytes = await multiLayerV4Decrypt(cipherBytes, keys);

                            const metaLen = new DataView(decBytes.buffer, decBytes.byteOffset, 4).getUint32(0, true);
                            const metaJsonBytes = decBytes.subarray(4, 4 + metaLen);
                            const meta = JSON.parse(new TextDecoder().decode(metaJsonBytes));
                            const rawData = decBytes.subarray(4 + metaLen);

                            decryptedFileName = meta.name || "decrypted_file";
                            decryptedFileBlob = new Blob([rawData], { type: meta.type || "application/octet-stream" });

                            $('outputText').value = `[DECRYPTED FILE: ${decryptedFileName} (${(rawData.length / 1024).toFixed(1)} KB)]\nAEAD Authentication Passed — 100% Intact Integrity.`;
                            $('downloadBtn').style.display = '';
                            $('verifiedBadge').classList.add('show');
                            $('resultSection').classList.add('show');
                            toast('File decrypted successfully', 'success');
                        } else if (mode === 'image') {
                            if (!imgData) { toast('Select an image first', 'error'); setButtonBusy(btn, false); return; }
                            const cv = $('workCanvas');
                            const cx = cv.getContext('2d', { willReadFrequently: true });
                            cv.width = imgData.w;
                            cv.height = imgData.h;
                            cx.drawImage(imgData.img, 0, 0);
                            const id = cx.getImageData(0, 0, cv.width, cv.height);
                            const wm = hasWM(id);
                            if (!wm) showWarning('imageWarning'); else $('verifiedBadge').classList.add('show');
                            procImg(cv, cx, keys, false);
                            const url = cv.toDataURL('image/png');
                            $('resultImage').src = url;
                            $('resultImage').classList.add('show');
                            $('outputText').style.display = 'none';
                            $('downloadBtn').style.display = '';
                            $('resultSection').classList.add('show');
                            toast('Image decrypted', 'success');
                        } else if (mode === 'stego') {
                            if (!stegoImgData) { toast('Select carrier image first', 'error'); setButtonBusy(btn, false); return; }
                            const cv = $('workCanvas');
                            const cx = cv.getContext('2d', { willReadFrequently: true });
                            cv.width = stegoImgData.w;
                            cv.height = stegoImgData.h;
                            cx.drawImage(stegoImgData.img, 0, 0);
                            const result = extractTxt(cv, cx, keys);
                            if (result) {
                                $('outputText').value = result;
                                $('verifiedBadge').classList.add('show');
                                $('resultSection').classList.add('show');
                                toast('Hidden text extracted successfully', 'success');
                            } else {
                                showWarning('stegoWarning');
                                toast('No hidden text found', 'error');
                                $('resultSection').classList.add('show');
                            }
                        }
                    } catch (er) {
                        toast('Decryption failed', 'error');
                        if (mode === 'files') showWarning('fileWarning');
                    }
                    setButtonBusy(btn, false);
                }, 40);
            });
        }

        // Copy & Download Result Handlers
        if ($('copyResultBtn')) {
            $('copyResultBtn').addEventListener('click', async () => {
                const out = $('outputText');
                const img = $('resultImage');
                if (out && out.style.display !== 'none' && out.value) {
                    const ok = await safeCopy(out.value);
                    toast(ok ? 'Copied to clipboard' : 'Copy failed', ok ? 'success' : 'error');
                } else if (img && img.classList.contains('show') && img.src) {
                    const ok = await safeCopyImg(img.src);
                    toast(ok ? 'Image copied' : 'Long press to save', ok ? 'success' : 'info');
                } else toast('No content', 'error');
            });
        }

        if ($('downloadBtn')) {
            $('downloadBtn').addEventListener('click', () => {
                const img = $('resultImage');
                if (img && img.src && img.classList.contains('show')) {
                    safeDl(img.src, mode === 'stego' ? 'salist_hidden.png' : 'salist_encrypted.png');
                } else if (encryptedFileBlob) {
                    safeDl(encryptedFileBlob, decryptedFileName);
                } else if (decryptedFileBlob) {
                    safeDl(decryptedFileBlob, decryptedFileName);
                }
            });
        }

        // Global Keybindings
        document.addEventListener('keydown', e => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                if ($('encryptBtn') && $('mainActionsSection').style.display !== 'none') $('encryptBtn').click();
            }
            if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'Enter') {
                e.preventDefault();
                if ($('decryptBtn') && $('mainActionsSection').style.display !== 'none') $('decryptBtn').click();
            }
        });

        if (isTg) {
            try {
                window.Telegram.WebApp.ready();
                window.Telegram.WebApp.expand();
            } catch (e) { }
        }
    });
})();
