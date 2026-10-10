/* Man-in-the-Middle attack on Diffie-Hellman
   VTU Cryptography & Network Security (BCS703)
   Notation follows the class notes:
   Sender A (private A, public A1), Receiver B (private B, public B1),
   Attacker D (private D1, D2, public D3, D4), keys K1 and K2. */

const $ = (id) => document.getElementById(id);

const DEFAULTS = { q: 23, g: 5, A: 6, B: 15, D1: 13, D2: 9 };
const INPUT_IDS = { q: "inQ", g: "inG", A: "inA", B: "inB", D1: "inD1", D2: "inD2" };
const TOTAL_STEPS = 7;

/* ---------- Maths helpers ---------- */

function modPow(base, exp, mod) {
  let result = 1n;
  let b = BigInt(base) % BigInt(mod);
  let e = BigInt(exp);
  const m = BigInt(mod);
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return Number(result);
}

function isPrime(n) {
  if (n < 2) return false;
  for (let i = 2; i * i <= n; i++) {
    if (n % i === 0) return false;
  }
  return true;
}

function escapeHtml(text) {
  return text.replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

/* ---------- Stand-in cipher: E(K, M) is a Caesar shift ---------- */

const shiftFromKey = (key) => (key % 25) + 1;

function shiftText(text, shift) {
  return text.replace(/[a-z]/gi, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + shift + 26 * 26) % 26) + base);
  });
}

const E = (key, text) => shiftText(text, shiftFromKey(key));
const Dec = (key, text) => shiftText(text, -shiftFromKey(key));

/* ---------- Inputs and key computation ---------- */

function readParams() {
  const p = {};
  for (const k of Object.keys(INPUT_IDS)) p[k] = Number($(INPUT_IDS[k]).value);

  if (Object.values(p).some((v) => !Number.isInteger(v))) {
    return { error: "Every value must be a whole number." };
  }
  if (p.q < 5 || p.q > 1000003 || !isPrime(p.q)) {
    return { error: "q must be a prime number between 5 and 1,000,003, for example 23." };
  }
  if (p.g < 2 || p.g > p.q - 2) {
    return { error: "g must be between 2 and q - 2." };
  }
  const names = { A: "A", B: "B", D1: "D1", D2: "D2" };
  for (const k of Object.keys(names)) {
    if (p[k] < 2 || p[k] > p.q - 2) {
      return { error: "Private key " + names[k] + " must be between 2 and q - 2." };
    }
  }
  if (p.D1 === p.D2) {
    return { error: "The attacker needs two different private keys, so D1 and D2 must differ." };
  }
  return p;
}

// Every value from the notes' 7 steps
function computeKeys(p) {
  const { q, g, A, B, D1, D2 } = p;
  const A1 = modPow(g, A, q);
  const B1 = modPow(g, B, q);
  const D3 = modPow(g, D1, q);
  const D4 = modPow(g, D2, q);
  return {
    A1, B1, D3, D4,
    K2att: modPow(A1, D2, q),   // step 3: Attacker  K2 = (A1)^D2 mod q
    K1rec: modPow(D3, B, q),    // step 4: Receiver  K1 = (D3)^B mod q
    K1att: modPow(B1, D1, q),   // step 6: Attacker  K1 = (B1)^D1 mod q
    K2snd: modPow(D4, A, q)     // step 7: Sender    K2 = (D4)^A mod q
  };
}

/* ---------- The 7 steps from the notes ---------- */

function stepsFor(p, k) {
  const { q, g, A, B, D1, D2 } = p;
  return [
    {
      text: "Attacker prepares for the attack by generating 2 random private keys D<sub>1</sub>, D<sub>2</sub> and then computing the corresponding public keys D<sub>3</sub> and D<sub>4</sub>.",
      calc: "D<sub>3</sub> = g<sup>D<sub>1</sub></sup> mod q = " + g + "<sup>" + D1 + "</sup> mod " + q + " = " + k.D3 +
            "<br>D<sub>4</sub> = g<sup>D<sub>2</sub></sup> mod q = " + g + "<sup>" + D2 + "</sup> mod " + q + " = " + k.D4
    },
    {
      text: "Sender transmits A<sub>1</sub> to Receiver.",
      calc: "A<sub>1</sub> = g<sup>A</sup> mod q = " + g + "<sup>" + A + "</sup> mod " + q + " = " + k.A1
    },
    {
      text: "Attacker intercepts A<sub>1</sub> and transmits D<sub>3</sub> to Receiver. Attacker also calculates K<sub>2</sub> = (A<sub>1</sub>)<sup>D<sub>2</sub></sup> mod q.",
      calc: "K<sub>2</sub> = " + k.A1 + "<sup>" + D2 + "</sup> mod " + q + " = " + k.K2att
    },
    {
      text: "Receiver receives D<sub>3</sub> and calculates K<sub>1</sub> = (D<sub>3</sub>)<sup>B</sup> mod q.",
      calc: "K<sub>1</sub> = " + k.D3 + "<sup>" + B + "</sup> mod " + q + " = " + k.K1rec
    },
    {
      text: "Receiver transmits B<sub>1</sub> to Sender.",
      calc: "B<sub>1</sub> = g<sup>B</sup> mod q = " + g + "<sup>" + B + "</sup> mod " + q + " = " + k.B1
    },
    {
      text: "Attacker intercepts B<sub>1</sub> and transmits D<sub>4</sub> to Sender. Attacker calculates K<sub>1</sub> = (B<sub>1</sub>)<sup>D<sub>1</sub></sup> mod q.",
      calc: "K<sub>1</sub> = " + k.B1 + "<sup>" + D1 + "</sup> mod " + q + " = " + k.K1att
    },
    {
      text: "Sender receives D<sub>4</sub> and calculates K<sub>2</sub> = (D<sub>4</sub>)<sup>A</sup> mod q.",
      calc: "K<sub>2</sub> = " + k.D4 + "<sup>" + A + "</sup> mod " + q + " = " + k.K2snd
    }
  ];
}

/* ---------- Block diagram (SVG) ---------- */

const SENDER_X = 130, LANE_L = 455, LANE_R = 495, RECEIVER_X = 830, MID_X = 475;

// exponent in SVG text, then the rest of the text back on the baseline
const sup = (e, rest) =>
  '<tspan class="sp" dy="-6">' + e + '</tspan><tspan dy="6">' + (rest || " ") + "</tspan>";

function svgBox(step, cx, y, w, lines, color) {
  const h = 36 + (lines.length - 1) * 19;
  let out = '<g class="el" data-step="' + step + '"><rect class="bx ' + color + '" x="' + (cx - w / 2) +
    '" y="' + y + '" width="' + w + '" height="' + h + '" rx="6"/>';
  lines.forEach((l, i) => {
    out += '<text class="' + (l.cls || "bt") + '" x="' + cx + '" y="' + (y + 23 + i * 19) +
      '" text-anchor="middle">' + l.t + "</text>";
  });
  return out + "</g>";
}

function svgArrow(step, x1, x2, y, color, label) {
  const dir = x2 > x1 ? 1 : -1;
  const head = x2 + "," + y + " " + (x2 - dir * 13) + "," + (y - 7) + " " + (x2 - dir * 13) + "," + (y + 7);
  return '<g class="el" data-step="' + step + '">' +
    '<line class="ar ' + color + '" x1="' + x1 + '" y1="' + y + '" x2="' + (x2 - dir * 10) + '" y2="' + y + '"/>' +
    '<polygon class="ah ' + color + '" points="' + head + '"/>' +
    '<text class="al" x="' + (x1 + x2) / 2 + '" y="' + (y - 9) + '" text-anchor="middle">' + label + "</text></g>";
}

function buildDiagram(p, k) {
  const header = (cx, w, label) =>
    '<g class="hdr"><rect x="' + (cx - w / 2) + '" y="14" width="' + w + '" height="40" rx="4"/>' +
    '<text x="' + cx + '" y="41" text-anchor="middle">' + label + "</text></g>";

  let s = '<svg viewBox="0 0 960 815" role="img" aria-label="Block diagram: Sender A, Attacker D and Receiver B exchanging public keys">';

  // lifelines
  s += '<line class="life" x1="' + SENDER_X + '" y1="54" x2="' + SENDER_X + '" y2="760"/>';
  s += '<line class="life" x1="' + LANE_L + '" y1="54" x2="' + LANE_L + '" y2="760"/>';
  s += '<line class="life" x1="' + LANE_R + '" y1="54" x2="' + LANE_R + '" y2="760"/>';
  s += '<line class="life" x1="' + RECEIVER_X + '" y1="54" x2="' + RECEIVER_X + '" y2="760"/>';

  s += header(SENDER_X, 150, "Sender A") + header(MID_X, 160, "Attacker D") + header(RECEIVER_X, 160, "Receiver B");

  // Sender: private key A, public key A1
  s += svgBox(2, SENDER_X, 80, 220, [
    { t: "Private Key A" },
    { t: "Public Key A₁" },
    { t: "A = " + p.A + ", A₁ = " + k.A1, cls: "bv" }
  ], "alice");

  // Step 2: A1 to the attacker's left lane
  s += svgArrow(2, SENDER_X, LANE_L, 190, "alice", "Public key A₁");

  // Step 1: attacker's keys
  s += svgBox(1, MID_X, 210, 270, [
    { t: "Private Keys D₁, D₂" },
    { t: "Public Keys D₃, D₄" },
    { t: "D₁=" + p.D1 + ", D₂=" + p.D2 + ", D₃=" + k.D3 + ", D₄=" + k.D4, cls: "bv" }
  ], "evil");

  // Step 3: D3 to the receiver, attacker computes K2
  s += svgArrow(3, LANE_R, RECEIVER_X, 318, "evil", "Public key D₃");
  s += svgBox(3, MID_X, 335, 270, [
    { t: "Secret Key K₂" },
    { t: "= (A₁)" + sup("D₂", " mod q") },
    { t: "= " + k.K2att, cls: "bv" }
  ], "evil");

  // Step 4: receiver keys and K1
  s += svgBox(4, RECEIVER_X, 335, 220, [
    { t: "Private Key B" },
    { t: "Public Key B₁" },
    { t: "B = " + p.B + ", B₁ = " + k.B1, cls: "bv" }
  ], "bob");
  s += svgBox(4, RECEIVER_X, 425, 220, [
    { t: "Secret Key K₁" },
    { t: "= (D₃)" + sup("B", " mod q") },
    { t: "= " + k.K1rec, cls: "bv" }
  ], "bob");

  // Step 5: B1 to the attacker's right lane
  s += svgArrow(5, RECEIVER_X, LANE_R, 530, "bob", "Public key B₁");

  // Step 6: D4 to the sender, attacker computes K1
  s += svgBox(6, MID_X, 548, 270, [
    { t: "Secret Key K₁" },
    { t: "= (B₁)" + sup("D₁", " mod q") },
    { t: "= " + k.K1att, cls: "bv" }
  ], "evil");
  s += svgArrow(6, LANE_L, SENDER_X, 655, "evil", "Public key D₄");

  // Step 7: sender computes K2
  s += svgBox(7, SENDER_X, 670, 220, [
    { t: "Secret Key K₂" },
    { t: "= (D₄)" + sup("A", " mod q") },
    { t: "= " + k.K2snd, cls: "bv" }
  ], "alice");

  s += '<g class="el" data-step="7">' +
    '<text class="red" x="300" y="785" text-anchor="middle">Sender and the Attacker</text>' +
    '<text class="red" x="300" y="805" text-anchor="middle">share the secret key K₂</text>' +
    '<text class="red" x="660" y="785" text-anchor="middle">Attacker and the Receiver</text>' +
    '<text class="red" x="660" y="805" text-anchor="middle">share the secret key K₁</text></g>';

  return s + "</svg>";
}

/* ---------- Stepper state ---------- */

let params = null;
let keys = null;
let steps = [];
let current = 0;
let timer = null;

function stopPlay() {
  if (timer) clearInterval(timer);
  timer = null;
  $("btnPlay").textContent = "Play";
}

function setStep(n) {
  current = Math.max(0, Math.min(TOTAL_STEPS, n));

  document.querySelectorAll("#diagram .el").forEach((el) => {
    const s = Number(el.getAttribute("data-step"));
    el.classList.toggle("pending", s > current);
    el.classList.toggle("active", s === current);
  });

  document.querySelectorAll("#stepList > li").forEach((li, i) => {
    const num = i + 1;
    li.classList.toggle("pending", num > current);
    li.classList.toggle("active", num === current);
    li.querySelector(".calc").hidden = num > current;
  });

  $("stepNow").innerHTML = current === 0
    ? "Step 0 of " + TOTAL_STEPS + ". Press Next step to begin."
    : "Step " + current + " of " + TOTAL_STEPS + ": " + steps[current - 1].text;

  $("btnPrev").disabled = current === 0;
  $("btnNext").disabled = current === TOTAL_STEPS;

  const note = $("afterNote");
  if (current === TOTAL_STEPS) {
    const okA = keys.K2snd === keys.K2att;
    const okB = keys.K1rec === keys.K1att;
    note.innerHTML =
      "<p>At this point, Receiver B and Sender A think that they share the secret key, but instead " +
      "B and D share the secret key K<sub>1</sub> (" + keys.K1rec + ") and A and D share the secret key K<sub>2</sub> (" + keys.K2snd + ").</p>" +
      "<p>Check: Sender's K<sub>2</sub> = Attacker's K<sub>2</sub> " + (okA ? "✓" : "✗") +
      " &nbsp; and &nbsp; Receiver's K<sub>1</sub> = Attacker's K<sub>1</sub> " + (okB ? "✓" : "✗") + ".</p>";
    note.hidden = false;
  } else {
    note.hidden = true;
  }
}

function buildSteps() {
  $("stepList").innerHTML = steps
    .map((s) => "<li><span>" + s.text + '</span><span class="calc" hidden>' + s.calc + "</span></li>")
    .join("");
}

function showError(id, text) {
  const el = $(id);
  el.textContent = text || "";
  el.hidden = !text;
}

function rebuild() {
  stopPlay();
  const p = readParams();
  if (p.error) {
    showError("kxError", p.error);
    return false;
  }
  showError("kxError", "");
  params = p;
  keys = computeKeys(p);
  steps = stepsFor(p, keys);
  $("diagram").innerHTML = buildDiagram(p, keys);
  buildSteps();
  setStep(0);
  return true;
}

/* ---------- Message communication (Steps 1 to 3 in the notes) ---------- */

function hop(cls, who, sub, lines, extra) {
  const body = lines
    .map((l) => '<p><span class="lbl">' + l[0] + ':</span> <span class="val ' + (l[2] || "") + '">' + l[1] + "</span></p>")
    .join("");
  return '<div class="hop ' + cls + (extra || "") + '"><div class="who">' + who + "<small>" + sub + "</small></div>" +
    '<div class="body">' + body + "</div></div>";
}

function renderMessage() {
  const p = readParams();
  if (p.error) {
    showError("msgError", p.error + " (change them in the Block Diagram section above)");
    return;
  }
  const M = $("msg").value.trim();
  const N = $("tamper").value.trim();
  const mode = document.querySelector('input[name="mode"]:checked').value;

  if (!M) { showError("msgError", "Enter a message M for the Sender to send."); return; }
  if (mode === "modify" && !N) { showError("msgError", "Enter the attacker's message N."); return; }
  showError("msgError", "");

  const k = computeKeys(p);
  const K2 = k.K2snd;   // shared by Sender and Attacker
  const K1 = k.K1rec;   // shared by Attacker and Receiver
  const e = escapeHtml;

  const c1 = E(K2, M);          // Step 1
  const recovered = Dec(k.K2att, c1); // Step 2
  const cM = E(K1, M);          // Step 3, eavesdrop
  const cN = E(K1, N || M);     // Step 3, modify
  const sentCipher = mode === "eavesdrop" ? cM : cN;
  const received = Dec(k.K1rec, sentCipher);
  const modified = received !== M;

  let html = "";

  html += hop("alice", "Step 1", "Sender sends an encrypted message M : E(K₂, M)", [
    ["K₂ (shared with Attacker)", K2 + " (shift " + shiftFromKey(K2) + ")"],
    ["M", e(M)],
    ["E(K₂, M)", e(c1), "cipher"]
  ]);

  html += hop("mallory", "Step 2", "Attacker intercepts the encrypted message and decrypts to recover M", [
    ["Decrypts with K₂", k.K2att + " (shift " + shiftFromKey(k.K2att) + ")"],
    ["Recovered M", e(recovered)]
  ]);

  html += hop("mallory", "Step 3", "Attacker sends Receiver E(K₁, M) | E(K₁, N)", [
    ["K₁ (shared with Receiver)", K1 + " (shift " + shiftFromKey(K1) + ")"],
    ["E(K₁, M) — eavesdrops", e(cM), "cipher"],
    ["E(K₁, N) — modifies, N = " + e(N), e(cN), "cipher"]
  ]);

  html += hop("mallory sent", "Sent to Receiver", mode === "eavesdrop" ? "E(K₁, M)" : "E(K₁, N)", [
    ["Attacker's choice", mode === "eavesdrop"
      ? "Just eavesdrops on the communication"
      : "Modifies the message"],
    ["Ciphertext", e(sentCipher), "cipher"]
  ]);

  html += hop("bob", "Receiver B", "decrypts with K₁", [
    ["Decrypts to", e(received), modified ? "changed" : ""]
  ]);

  $("relay").innerHTML = html;

  const v = $("msgVerdict");
  if (modified) {
    v.className = "verdict broken";
    v.innerHTML =
      "<p><code>E(K₁, N)</code>: the attacker modifies the message.</p>" +
      "<p>The modified message sent by the attacker becomes the main mode of communication, " +
      "which is the wrong message. Sender A never sent it, yet Receiver B accepts it.</p>";
  } else {
    v.className = "verdict broken";
    v.innerHTML =
      "<p><code>E(K₁, M)</code>: the attacker just eavesdrops on the communication.</p>" +
      "<p>Receiver B gets the correct message, but the attacker has read it, and neither A nor B can tell.</p>";
  }

  $("msgResult").hidden = false;
  $("msgEmpty").hidden = true;
}

/* ---------- Events ---------- */

Object.values(INPUT_IDS).forEach((id) => $(id).addEventListener("input", rebuild));

$("btnNext").addEventListener("click", () => { stopPlay(); if (params) setStep(current + 1); });
$("btnPrev").addEventListener("click", () => { stopPlay(); if (params) setStep(current - 1); });
$("btnAll").addEventListener("click", () => { stopPlay(); if (params) setStep(TOTAL_STEPS); });
$("btnReset").addEventListener("click", () => {
  Object.keys(DEFAULTS).forEach((key) => { $(INPUT_IDS[key]).value = DEFAULTS[key]; });
  rebuild();
});

$("btnPlay").addEventListener("click", () => {
  if (!params) return;
  if (timer) { stopPlay(); return; }
  if (current >= TOTAL_STEPS) setStep(0);
  $("btnPlay").textContent = "Pause";
  setStep(current + 1);
  timer = setInterval(() => {
    if (current >= TOTAL_STEPS) { stopPlay(); return; }
    setStep(current + 1);
    if (current >= TOTAL_STEPS) stopPlay();
  }, 2200);
});

$("runMsg").addEventListener("click", renderMessage);
document.querySelectorAll('input[name="mode"]').forEach((r) =>
  r.addEventListener("change", () => { if (!$("msgResult").hidden) renderMessage(); })
);
$("resetMsg").addEventListener("click", () => {
  $("msg").value = "Transfer 500 rupees to account 4421";
  $("tamper").value = "Transfer 500 rupees to account 9999";
  document.querySelector('input[name="mode"][value="modify"]').checked = true;
  showError("msgError", "");
  $("msgResult").hidden = true;
  $("msgEmpty").hidden = false;
});

rebuild();
