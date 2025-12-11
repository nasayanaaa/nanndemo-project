// app.js
// 暗号ツール + フィードバック送信（Formspree等）
// 保存: app.js を同じフォルダに置くこと

/* ---------- ユーティリティ ---------- */
const $ = id => document.getElementById(id);
function toBase64(bytes){ return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
function fromBase64(b64){ const s = atob(b64); const a = new Uint8Array(s.length); for(let i=0;i<s.length;i++) a[i]=s.charCodeAt(i); return a; }
function utf8ToBytes(str){ return new TextEncoder().encode(str); }
function bytesToUtf8(bytes){ return new TextDecoder().decode(bytes); }
function randBytes(n){ const b=new Uint8Array(n); crypto.getRandomValues(b); return b; }

/* ---------- 簡易暗号 ---------- */
function caesarEncrypt(text, shift){
  shift = ((+shift)%26+26)%26;
  return text.replace(/[A-Za-z]/g, c=>{
    const base = c<='Z' ? 65 : 97;
    return String.fromCharCode((c.charCodeAt(0)-base+shift)%26 + base);
  });
}
function caesarDecrypt(text, shift){ return caesarEncrypt(text, -shift); }

function vigenereEncrypt(text, key){
  if(!key) return text;
  let ki=0; key=key.toLowerCase();
  return text.split('').map(ch=>{
    if(/[A-Za-z]/.test(ch)){
      const base = ch<='Z' ? 65 : 97;
      const k = key[ki%key.length].toLowerCase().charCodeAt(0)-97;
      ki++;
      return String.fromCharCode((ch.charCodeAt(0)-base+k)%26+base);
    } else return ch;
  }).join('');
}
function vigenereDecrypt(text, key){
  if(!key) return text;
  let ki=0; key=key.toLowerCase();
  return text.split('').map(ch=>{
    if(/[A-Za-z]/.test(ch)){
      const base = ch<='Z' ? 65 : 97;
      const k = key[ki%key.length].toLowerCase().charCodeAt(0)-97;
      ki++;
      return String.fromCharCode((ch.charCodeAt(0)-base-k+26*10)%26+base);
    } else return ch;
  }).join('');
}

function xorOperate(text, key){
  if(!key) return toBase64(utf8ToBytes(text));
  const t = utf8ToBytes(text);
  const k = utf8ToBytes(key);
  const out = new Uint8Array(t.length);
  for(let i=0;i<t.length;i++) out[i]=t[i]^k[i % k.length];
  return toBase64(out);
}
function xorReverse(b64, key){
  if(!key) return bytesToUtf8(fromBase64(b64));
  const data = fromBase64(b64);
  const k = utf8ToBytes(key);
  const out = new Uint8Array(data.length);
  for(let i=0;i<data.length;i++) out[i]=data[i]^k[i % k.length];
  return bytesToUtf8(out);
}

/* ---------- AES-GCM（Web Crypto） ---------- */
/*
 Output format: Base64(salt) : Base64(iv) : Base64(ciphertext)
 Salt: 16 bytes, IV: 12 bytes
 PBKDF2 iterations: 200000
 */
async function deriveKeyFromPassword(password, salt, iterations=200000){
  const pwKey = await crypto.subtle.importKey('raw', utf8ToBytes(password), {name:'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256'},
    pwKey,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt','decrypt']
  );
}
async function aesEncrypt(plaintext, password){
  const salt = randBytes(16);
  const iv = randBytes(12);
  const key = await deriveKeyFromPassword(password, salt);
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv: iv}, key, utf8ToBytes(plaintext));
  return `${toBase64(salt)}:${toBase64(iv)}:${toBase64(ct)}`;
}
async function aesDecrypt(combined, password){
  const parts = combined.split(':');
  if(parts.length !== 3) throw new Error('形式不正（salt:iv:ciphertext の形式）');
  const salt = fromBase64(parts[0]);
  const iv = fromBase64(parts[1]);
  const ct = fromBase64(parts[2]);
  const key = await deriveKeyFromPassword(password, salt);
  const plain = await crypto.subtle.decrypt({name:'AES-GCM', iv: iv}, key, ct);
  return bytesToUtf8(new Uint8Array(plain));
}

/* ---------- UI ロジック ---------- */
const cipherSelect = $('cipher');
const paramsDiv = $('params');
function renderParams(){
  const cipher = cipherSelect.value;
  let html = '';
  if(cipher === 'caesar'){
    html = `<label>シフト量（整数）<input id="param_shift" type="number" value="3"></label>`;
  } else if(cipher === 'vigenere'){
    html = `<label>鍵（英字）<input id="param_key" type="text" placeholder="例: marisa"></label>`;
  } else if(cipher === 'xor'){
    html = `<label>鍵（任意の文字列）<input id="param_key" type="text" placeholder="例: mysecret"></label>`;
  } else if(cipher === 'base64'){
    html = `<p class="small">Base64は可逆変換（可読性のための変換）。</p>`;
  } else if(cipher === 'aesgcm'){
    html = `<label>パスワード（復号に同じパスワードが必要）<input id="param_pw" type="password" placeholder="強いパスワードを入力"></label>
            <p class="small">AES-GCMを使います。出力は salt:iv:ciphertext（全てBase64）。</p>`;
  }
  paramsDiv.innerHTML = html;
}
cipherSelect.addEventListener('change', renderParams);
renderParams();

$('goBtn').addEventListener('click', async ()=>{
  const mode = $('mode').value;
  const cipher = $('cipher').value;
  const text = $('inputText').value || '';
  const outEl = $('output');
  try{
    if(cipher === 'caesar'){
      const shift = parseInt((document.getElementById('param_shift')||{value:0}).value || '0',10);
      outEl.textContent = (mode==='encrypt') ? caesarEncrypt(text, shift) : caesarDecrypt(text, shift);
    } else if(cipher === 'vigenere'){
      const key = (document.getElementById('param_key')||{value:''}).value || '';
      outEl.textContent = (mode==='encrypt') ? vigenereEncrypt(text, key) : vigenereDecrypt(text, key);
    } else if(cipher === 'base64'){
      outEl.textContent = (mode==='encrypt') ? btoa(unescape(encodeURIComponent(text))) : decodeURIComponent(escape(atob(text)));
    } else if(cipher === 'xor'){
      const key = (document.getElementById('param_key')||{value:''}).value || '';
      outEl.textContent = (mode==='encrypt') ? xorOperate(text, key) : xorReverse(text, key);
    } else if(cipher === 'aesgcm'){
      const pw = (document.getElementById('param_pw')||{value:''}).value || '';
      if(!pw) throw new Error('パスワードを入力してください');
      if(mode==='encrypt'){
        const res = await aesEncrypt(text, pw);
        outEl.textContent = res;
      } else {
        const res = await aesDecrypt(text.trim(), pw);
        outEl.textContent = res;
      }
    } else {
      outEl.textContent = '未知の方式';
    }
  } catch(e){
    outEl.textContent = 'エラー: ' + e.message;
  }
});

$('copyBtn').addEventListener('click', ()=>{
  const t = $('output').textContent || '';
  if(!t) return alert('コピーするテキストがありません');
  navigator.clipboard.writeText(t).then(()=> alert('コピーしました'), ()=> alert('コピーに失敗しました'));
});

/* 共有リンク（簡易） */
$('shareBtn').addEventListener('click', ()=>{
  const mode = $('mode').value;
  const cipher = $('cipher').value;
  const input = $('inputText').value || '';
  const params = {};
  if(cipher === 'caesar') params.shift = (document.getElementById('param_shift')||{}).value || '';
  if(cipher === 'vigenere' || cipher === 'xor') params.key = (document.getElementById('param_key')||{}).value || '';
  // AESのパスワードは含めない
  const payload = {mode, cipher, input, params};
  const frag = btoa(unescape(encodeURIComponent(JSON.stringify(payload))));
  const url = location.origin + location.pathname + '#tool:' + frag;
  navigator.clipboard.writeText(url).then(()=> alert('共有リンクをクリップボードにコピーしました'), ()=> alert('共有リンクコピー失敗'));
});

/* URLフラグメントから復元 */
(function tryLoadFromFragment(){
  if(!location.hash.startsWith('#tool:')) return;
  try{
    const frag = location.hash.slice(6);
    const json = decodeURIComponent(escape(atob(frag)));
    const payload = JSON.parse(json);
    $('mode').value = payload.mode || 'encrypt';
    $('cipher').value = payload.cipher || 'caesar';
    renderParams();
    $('inputText').value = payload.input || '';
    if(payload.params){
      if(payload.params.shift) document.getElementById('param_shift').value = payload.params.shift;
      if(payload.params.key) document.getElementById('param_key').value = payload.params.key;
    }
    if(payload.cipher === 'aesgcm') alert('注意: 共有リンクはAESのパスワードを含みません。復号にはパスワードが必要です。');
  } catch(e){
    console.warn('フラグメントの読み込みに失敗', e);
  }
})();

/* ---------- 意見箱ロジック（送信前にクライアント暗号化オプション） ---------- */
const encryptCheckbox = $('encryptBeforeSend');
const pwLabel = $('pwLabel');
const feedbackForm = $('feedbackForm');
const encryptedFlag = $('encryptedFlag');

encryptCheckbox.addEventListener('change', ()=>{
  if(encryptCheckbox.checked){
    pwLabel.classList.remove('hidden');
  } else {
    pwLabel.classList.add('hidden');
    $('feedbackPW').value = '';
  }
});

feedbackForm.addEventListener('submit', async (ev)=>{
  // Formspree等に送る前にメッセージを暗号化したい場合はここで変換
  if(encryptCheckbox.checked){
    ev.preventDefault(); // 一旦止める
    const pw = $('feedbackPW').value || '';
    if(!pw){
      alert('暗号化する場合はパスワードを入力してください（受信者が復号するための合言葉です）。');
      return;
    }
    const msgEl = $('feedbackMsg');
    const plain = msgEl.value || '';
    try{
      const ct = await aesEncrypt(plain, pw);
      // 置き換えて送信（元メッセージは上書き）
      msgEl.value = ct;
      encryptedFlag.value = 'true';
      // submit を再発火（無限ループ防止のため一度だけ）
      feedbackForm.removeEventListener('submit', arguments.callee);
      feedbackForm.submit();
    } catch(e){
      alert('暗号化に失敗しました: ' + e.message);
    }
  } else {
    // 普通に送る（暗号化フラグは false）
    encryptedFlag.value = 'false';
  }
});

/* 受信後のローカル復号（プレビュー用） */
$('previewDecrypt').addEventListener('click', async ()=>{
  const payload = prompt('復号したい暗号文（salt:iv:ciphertext の形式）を貼り付けてください。');
  if(!payload) return;
  const pw = prompt('復号に使うパスワードを入力してください（正しくないと復号できません）');
  if(pw === null) return;
  try{
    const plain = await aesDecrypt(payload.trim(), pw);
    alert('復号結果:\n\n' + plain);
  } catch(e){
    alert('復号に失敗しました: ' + e.message);
  }
});