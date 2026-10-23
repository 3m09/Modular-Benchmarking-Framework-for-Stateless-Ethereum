const { buildPoseidon } = require("circomlibjs");

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Listen for batches on stdin, one JSON array per line
    process.stdin.setEncoding("utf8");
    let buffer = "";

    process.stdin.on("data", (chunk) => {
        buffer += chunk;
        const lines = buffer.split("\n");
        buffer = lines.pop(); // keep incomplete line

        for (const line of lines) {
            if (!line.trim()) continue;
            const inputs = JSON.parse(line);          // e.g. [a, b, c, d]
            const result = F.toString(poseidon(inputs));
            process.stdout.write(result + "\n");
        }
    });
}

main();