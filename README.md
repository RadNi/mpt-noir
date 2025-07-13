# MPT Noir

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Noir-Tests](https://github.com/radni/mpt-noir/actions/workflows/noir.yml/badge.svg)](https://github.com/radni/mpt-noir/actions/workflows/noir.yml)

**This software is unaudited and should not be used in production. Use at your own risk.**

<hr>

**MPT Noir** includes tools to prove Ethereum Merkle Patricia Trie (MPT) proofs.



<br>

## Installation

In your `Nargo.toml` file, add the following dependency:

```toml
[dependencies]
mpt = { tag = "v0.2.0", git = "https://github.com/radni/mpt-noir" }
```

## Simple Usage
The [mpt-noirjs](https://github.com/radni/mpt-noirjs) package is made to facilitate witness generation for mpt-noir circuits. To generate inputs for address `"MY_ADDRESS"` against the latest block you can use the following:

```typescript

const provider = new ethers.JsonRpcProvider("RPC_URL")
const address = "MY_ADDRESS"
const output = await provider.send("eth_getProof", [address, [], "latest"])
const mpt_proof = getNodesFromProof(output.accountProof, address)
```

The `mpt_proof` contains all the data necessary to generate proof using the mpt-noir circuits. To see an elaborated example you can checkout [Balance Proof](https://github.com/RadNi/balance_proof) application. 

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/radni/mpt-noir/blob/main/LICENSE) file for details.
