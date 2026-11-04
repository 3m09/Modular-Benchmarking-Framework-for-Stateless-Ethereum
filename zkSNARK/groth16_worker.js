// Persistent Groth16 verifier: one JSON request per line on stdin,
// {"public": [...], "proof": {...}} -> "true" / "false" on stdout.
// Keeps Node.js start-up and verification-key parsing out of the timed path.
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const vkey = JSON.parse(fs.readFileSync(process.argv[2]));

const rl = require("readline").createInterface({ input: process.stdin });
let queue = Promise.resolve();
rl.on("line", (line) => {
    if (!line.trim()) return;
    queue = queue.then(async () => {
        let ok = false;
        try {
            const req = JSON.parse(line);
            ok = await snarkjs.groth16.verify(vkey, req.public, req.proof);
        } catch (e) {
            ok = false;
        }
        process.stdout.write((ok ? "true" : "false") + "\n");
    });
});
rl.on("close", () => queue.then(() => process.exit(0)));
