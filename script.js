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
        <h4>${title}</h4>async function runSimulation() {

    const message =
        document.getElementById("message").value.trim() || "HELLO";

    const mode =
        document.getElementById("attackMode").value;

    const steps =
        document.getElementById("simulationSteps");

    /* Clear previous steps */
    steps.innerHTML = "";
    steps.className = "";

    /* Initial state */

    document.getElementById("packetAB").textContent =
        message;

    document.getElementById("packetBB").textContent =
        "Waiting...";

    document.getElementById("attackerStatus").textContent =
        "Waiting for message...";

    document.getElementById("originalResult").textContent =
        message;

    document.getElementById("observedResult").textContent =
        "—";

    document.getElementById("receivedResult").textContent =
        "—";

    document.getElementById("securityResult").textContent =
        "Running...";


    /* =====================================================
       STEP 1 — ALICE SENDS MESSAGE
       ===================================================== */

    steps.innerHTML += `
        <div class="step">

            <div class="step-no">1</div>

            <div>
                <h4>Alice sends the message</h4>

                <p>
                    Alice sends:
                    <strong>"${message}"</strong>
                </p>
            </div>

        </div>
    `;


    await sleep(1000);


    /* =====================================================
       ATTACK MODE
       ===================================================== */

    if (mode === "attack") {

        /* Message reaches Mallory */

        document.getElementById("packetAB").textContent =
            message;

        document.getElementById("attackerStatus").textContent =
            `Intercepted: "${message}"`;

        document.getElementById("observedResult").textContent =
            message;


        steps.innerHTML += `
            <div class="step">

                <div class="step-no">2</div>

                <div>

                    <h4>Mallory intercepts the message</h4>

                    <p>
                        Mallory captures:
                        <strong>"${message}"</strong>
                    </p>

                </div>

            </div>
        `;


        await sleep(1200);


        /* =================================================
           MALLORY RELAYS MESSAGE
           ================================================= */

        document.getElementById("packetBB").textContent =
            message;

        document.getElementById("attackerStatus").textContent =
            `Relaying: "${message}"`;


        steps.innerHTML += `
            <div class="step">

                <div class="step-no">3</div>

                <div>

                    <h4>Mallory relays the message</h4>

                    <p>
                        Mallory forwards:
                        <strong>"${message}"</strong>
                        to Bob.
                    </p>

                </div>

            </div>
        `;


        await sleep(1200);


        /* =================================================
           BOB RECEIVES MESSAGE
           ================================================= */

        document.getElementById("packetBB").textContent =
            message;

        document.getElementById("receivedResult").textContent =
            message;

        document.getElementById("securityResult").textContent =
            "MITM risk demonstrated";


        document.getElementById("attackerStatus").textContent =
            `Message intercepted: "${message}"`;


        steps.innerHTML += `
            <div class="step">

                <div class="step-no">4</div>

                <div>

                    <h4>Bob receives the message</h4>

                    <p>
                        Bob receives:
                        <strong>"${message}"</strong>
                    </p>

                </div>

            </div>
        `;


    }

    /* =====================================================
       SECURE MODE
       ===================================================== */

    else {

        document.getElementById("packetAB").textContent =
            "Authenticated";

        document.getElementById("attackerStatus").textContent =
            "Blocked / detected";


        steps.innerHTML += `
            <div class="step">

                <div class="step-no">2</div>

                <div>

                    <h4>Authentication check</h4>

                    <p>
                        The connection authenticates the communicating
                        parties, reducing the risk of an unauthorized
                        intermediary.
                    </p>

                </div>

            </div>
        `;


        await sleep(1200);


        document.getElementById("packetBB").textContent =
            message;

        document.getElementById("receivedResult").textContent =
            message;

        document.getElementById("observedResult").textContent =
            "Protected";

        document.getElementById("securityResult").textContent =
            "Authenticated communication";


        steps.innerHTML += `
            <div class="step">

                <div class="step-no">3</div>

                <div>

                    <h4>Secure message delivery</h4>

                    <p>
                        Bob receives:
                        <strong>"${message}"</strong>
                        through the authenticated channel.
                    </p>

                </div>

            </div>
        `;


        await sleep(800);


        document.getElementById("attackerStatus").textContent =
            "No message obtained";


        steps.innerHTML += `
            <div class="step">

                <div class="step-no">4</div>

                <div>

                    <h4>Attacker is prevented</h4>

                    <p>
                        The simplified demonstration represents
                        Mallory as unable to silently impersonate
                        either endpoint.
                    </p>

                </div>

            </div>
        `;
    }
}
        <p>${text}</p>
      </div>
    </div>`;
}

