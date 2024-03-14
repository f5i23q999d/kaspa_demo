const { KaspaWallet } = require("@okxweb3/coin-kaspa");
const axios = require('axios');

async function test() {
    const hdPaths = [
        "m/44'/111111'/0'/0/0"
    ];

    for (const hdPath of hdPaths) {
        let wallet = new KaspaWallet();
        let p = {
            mnemonic: "reopen vivid parent want raw main filter rotate earth true fossil dream",
            hdPath
        };
        let privateKey = await wallet.getDerivedPrivateKey(p);
        let address = await wallet.getNewAddress(
            {
                privateKey
            }
        );
        console.log(hdPath, '  ', address.address); // kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x
        const node_url = 'https://api.kaspa.org';
        const utxo = (await axios.get(`${node_url}/addresses/${address.address}/utxos`)).data;
        /*
                [
                    {
                        "address": "kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x",
                        "outpoint": {
                            "transactionId": "6e581d0ca2bf8d46e6503084805b3c3d384191c430c9283702925cd4e048912d",
                            "index": 0
                        },
                        "utxoEntry": {
                            "amount": "1000000",
                            "scriptPublicKey": {
                                "scriptPublicKey": "200395c7c9703e0ff81596043f0a5e00684f860a1ab0f24c5a94931d1e0d94c4beac"
                            },
                            "blockDaaScore": "73995685"
                        }
                    }
                ]
        */
        const param = {
            data: {
                inputs: [
                    {
                        txId: "6e12b8400b723e0a3683f284e36cf73ff061beb01bee4c07f8f30086e5e0a3a9",
                        vOut: 0,
                        address: "kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x",
                        amount: 1000000,
                    },
                ],
                outputs: [
                    {
                        address: "kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x",
                        amount: 990000,
                    },
                ],
                address: "kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x",
                fee: 10000,
            },
            privateKey: privateKey,
        };

        const tx = await wallet.signTransaction(param);
        console.log(tx);
        /*
                {
                    "transaction": {
                        "version": 0,
                            "inputs": [
                                {
                                    "previousOutpoint": {
                                        "transactionId": "6e12b8400b723e0a3683f284e36cf73ff061beb01bee4c07f8f30086e5e0a3a9",
                                        "index": 0
                                    },
                                    "signatureScript": "411296992d324a2388d4ec5169ea869239e616ae81ae0e5aabad95cb524d6f25183e550aa0179d6ba3a24b2dff278d445e979b29d70fb3543e3bf2acfb937261b901",
                                    "sequence": "0",
                                    "sigOpCount": 1
                                }
                            ],
                                "outputs": [
                                    {
                                        "scriptPublicKey": {
                                            "version": 0,
                                            "scriptPublicKey": "200395c7c9703e0ff81596043f0a5e00684f860a1ab0f24c5a94931d1e0d94c4beac"
                                        },
                                        "amount": 990000
                                    }
                                ],
                                    "lockTime": "0",
                                        "subnetworkId": "0000000000000000000000000000000000000000"
                    },
                    "allowOrphan": false
                }
        */
    }
}

test()


