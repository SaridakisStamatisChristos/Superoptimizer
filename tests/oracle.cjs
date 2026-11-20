const fs = require("node:fs");
const { EVM } = require("@ethereumjs/evm");
const { Common, Chain, Hardfork } = require("@ethereumjs/common");

async function main() {
  const common = new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Shanghai });
  const evm = await EVM.create({ common });
  const cases = JSON.parse(fs.readFileSync(0, "utf8"));
  for (const { source, initial, output, gas } of cases) {
    const prefix = initial.map((word) => "7f" + word.padStart(64, "0")).join("");
    const result = await evm.runCode({
      code: Buffer.from(prefix + source, "hex"),
      gasLimit: 100000n,
    });
    if (result.exceptionError) throw result.exceptionError;
    const actual = result.runState.stack.getStack().map((word) => word.toString(16));
    if (result.executionGasUsed - BigInt(3 * initial.length) !== BigInt(gas) ||
        JSON.stringify(actual) !== JSON.stringify(output)) {
      throw new Error(JSON.stringify({ source, initial, output, actual, gas }));
    }
  }
  console.log(`EthereumJS Shanghai oracle matched ${cases.length} executions`);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
