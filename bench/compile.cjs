const fs = require("node:fs");
const solc = require("solc");

const source = fs.readFileSync(__dirname + "/Samples.sol", "utf8");
const contracts = {};
for (const viaIR of [false, true]) {
  const output = JSON.parse(solc.compile(JSON.stringify({
    language: "Solidity",
    sources: { "Samples.sol": { content: source } },
    settings: {
      evmVersion: "shanghai",
      viaIR,
      optimizer: { enabled: true, runs: 200 },
      metadata: { appendCBOR: false, bytecodeHash: "none" },
      outputSelection: { "*": { "*": ["evm.deployedBytecode.object"] } },
    },
  })));
  const errors = (output.errors || []).filter((entry) => entry.severity === "error");
  if (errors.length) throw new Error(JSON.stringify(errors));
  const mode = viaIR ? "via-ir" : "legacy";
  contracts[mode] = output.contracts["Samples.sol"].Samples.evm.deployedBytecode.object;
}
console.log(JSON.stringify(contracts));
