/* =========================================================
   MAN-IN-THE-MIDDLE ATTACK - EDUCATIONAL SIMULATOR
   Safe local demonstration only. No network traffic is sent.
   ========================================================= */

const $ = (id) => document.getElementById(id);

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function setStep(container, number, title, text) {
  const existing = container.className.includes("empty") ? "" : container.innerHTML;
  container.className = "";
  container.innerHTML = existing + `
    <div class="step">
      <div class="step-no">${number}</div>
      <div>
        <h4>${title}</h4>
        <p>${text}</p>
      </div>
    </div>`;
}

async function runSimulation() {
  const message = $("message").value.trim() || "HELLO";
  const mode = $("attackMode").value;

  const steps = $("simulationSteps");
  steps.innerHTML = "";
  steps.className = "";

  $("packetAB").textContent = "Sending…";
  $("packetBB").textContent = "Waiting…";
  $("attackerStatus").textContent = "Observing the channel…";

  $("originalResult").textContent = message;
  $("observedResult").textContent = "—";
  $("receivedResult").textContent = "—";
  $("securityResult").textContent = "Running…";

  setStep(steps, 1, "Alice sends", `Alice prepares the message: “${message}”.`);

  await sleep(550);

  if (mode === "attack") {
    $("packetAB").textContent = "Intercepted";
    $("attackerStatus").textContent = "Message observed";
    setStep(steps, 2, "Mallory intercepts", "Mallory is positioned between Alice and Bob and receives the traffic before Bob.");

    await sleep(650);

    $("observedResult").textContent = message;
    $("packetBB").textContent = "Relaying…";
    setStep(steps, 3, "Mallory relays", "For this demonstration, Mallory reads the message and forwards it to Bob. Real-world impact depends on the protocol and protections in use.");

    await sleep(650);

    $("packetBB").textContent = "Delivered";
    $("receivedResult").textContent = message;
    $("securityResult").textContent = "Authentication is missing — MITM risk demonstrated";
    setStep(steps, 4, "Bob receives", "Bob receives the message but the simplified scenario provides no cryptographic proof that the communication path is authentic.");

  } else {
    $("packetAB").textContent = "Authenticated";
    $("attackerStatus").textContent = "Blocked / detected";
    setStep(steps, 2, "Authentication check", "The endpoints authenticate the connection. An unauthorized intermediary cannot silently impersonate an endpoint.");

    await sleep(650);

    $("observedResult").textContent = "Protected";
    $("packetBB").textContent = "Secure channel";
    setStep(steps, 3, "Protected transport", "The message is represented as protected in this educational simulation; no actual network traffic is generated.");

    await sleep(650);

    $("packetBB").textContent = "Delivered";
    $("receivedResult").textContent = message;
    $("securityResult").textContent = "Authentication enabled — MITM risk reduced";
    setStep(steps, 4, "Bob receives", "Bob receives the message through an authenticated secure channel.");
  }
}

function resetSimulation() {
  $("packetAB").textContent = "Message";
  $("packetBB").textContent = "Message";
  $("attackerStatus").textContent = "Waiting…";
  $("originalResult").textContent = "—";
  $("observedResult").textContent = "—";
  $("receivedResult").textContent = "—";
  $("securityResult").textContent = "—";
  $("simulationSteps").className = "empty";
  $("simulationSteps").textContent = "Click “Run Simulation” to begin.";
}

/* Small modular exponentiation implementation for the classroom demo. */
function modPow(base, exponent, modulus) {
  let result = 1;
  base %= modulus;
  while (exponent > 0) {
    if (exponent % 2 === 1) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exponent = Math.floor(exponent / 2);
  }
  return result;
}

function runDiffieHellmanMITM() {
  /*
    Fixed classroom values:
      p = 23, g = 5
    Alice private a = 6
    Bob private b = 15
    Mallory substitutes two public values using private values
      m1 = 13 and m2 = 9

    This is a mathematical visualization, not a real network attack.
  */
  const p = 23;
  const g = 5;
  const a = 6;
  const b = 15;
  const m1 = 13;
  const m2 = 9;

  const A = modPow(g, a, p);
  const B = modPow(g, b, p);
  const M1 = modPow(g, m1, p);
  const M2 = modPow(g, m2, p);

  const mallorySecretA = modPow(A, m1, p);
  const mallorySecretB = modPow(B, m2, p);

  const aliceSecret = modPow(M1, a, p);
  const bobSecret = modPow(M2, b, p);

  $("pValue").textContent = p;
  $("gValue").textContent = g;
  $("alicePrivate").textContent = a;
  $("alicePublic").textContent = A;
  $("bobPrivate").textContent = b;
  $("bobPublic").textContent = B;
  $("malloryPublic1").textContent = M1;
  $("malloryPublic2").textContent = M2;
  $("mallorySecretA").textContent = mallorySecretA;
  $("mallorySecretB").textContent = mallorySecretB;
  $("bobSecret").textContent = bobSecret;

  const card = $("runDH").parentElement;
  let note = card.querySelector(".dh-result-note");
  if (!note) {
    note = document.createElement("p");
    note.className = "dh-result-note";
    note.style.marginTop = "12px";
    note.style.color = "#047857";
    note.style.fontWeight = "700";
    card.appendChild(note);
  }

  note.textContent =
    `Alice's computed secret = ${aliceSecret}; Bob's computed secret = ${bobSecret}. ` +
    `They differ because Mallory substituted public values.`;
}

document.addEventListener("DOMContentLoaded", () => {
  $("runSimulation").addEventListener("click", runSimulation);
  $("resetSimulation").addEventListener("click", resetSimulation);
  $("runDH").addEventListener("click", runDiffieHellmanMITM);
});
