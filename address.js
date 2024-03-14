const HDKey = require('hdkey');
const bip39 = require('bip39');

const GENERATOR1 = [0x98, 0x79, 0xf3, 0xae, 0x1e];
const GENERATOR2 = [0xf2bc8e61, 0xb76d99e2, 0x3e5fb3c4, 0x2eabe2a8, 0x4f43e470];

function polymod(data) {
    // Treat c as 8 bits + 32 bits
    var c0 = 0, c1 = 1, C = 0;
    for (var j = 0; j < data.length; j++) {
        // Set C to c shifted by 35
        C = c0 >>> 3;
        // 0x[07]ffffffff
        c0 &= 0x07;
        // Shift as a whole number
        c0 <<= 5;
        c0 |= c1 >>> 27;
        // 0xffffffff >>> 5
        c1 &= 0x07ffffff;
        c1 <<= 5;
        // xor the last 5 bits
        c1 ^= data[j];
        for (var i = 0; i < GENERATOR1.length; ++i) {
            if (C & (1 << i)) {
                c0 ^= GENERATOR1[i];
                c1 ^= GENERATOR2[i];
            }
        }
    }
    c1 ^= 1;
    // Negative numbers -> large positive numbers
    if (c1 < 0) {
        c1 ^= 1 << 31;
        c1 += (1 << 30) * 2;
    }
    // Unless bitwise operations are used,
    // numbers are consisting of 52 bits, except
    // the sign bit. The result is max 40 bits,
    // so it fits perfectly in one number!
    return c0 * (1 << 30) * 4 + c1;
}

function convertBits(data, from, to, strictMode) {
    var length = strictMode
        ? Math.floor(data.length * from / to)
        : Math.ceil(data.length * from / to);
    var mask = (1 << to) - 1;
    var result = new Uint8Array(length);
    var index = 0;
    var accumulator = 0;
    var bits = 0;
    for (var i = 0; i < data.length; ++i) {
        var value = data[i];
        validate(0 <= value && (value >> from) === 0, 'Invalid value: ' + value + '.');
        accumulator = (accumulator << from) | value;
        bits += from;
        while (bits >= to) {
            bits -= to;
            result[index] = (accumulator >> bits) & mask;
            ++index;
        }
    }
    if (!strictMode) {
        if (bits > 0) {
            result[index] = (accumulator << (to - bits)) & mask;
            ++index;
        }
    } else {
        validate(
            bits < from && ((accumulator << (to - bits)) & mask) === 0,
            'Input cannot be converted to ' + to + ' bits without padding, but strict mode was used.'
        );
    }
    return result;
}

function checksumToArray(checksum) {
    const result = [];
    for (let i = 0; i < 8; ++i) {
        result.push(checksum & 31);
        checksum /= 32;
    }
    return result.reverse();
}


function validate(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function convert(data, from, to, strictMode) {
    var length = strictMode
        ? Math.floor(data.length * from / to)
        : Math.ceil(data.length * from / to);
    var mask = (1 << to) - 1;
    var result = new Uint8Array(length);
    var index = 0;
    var accumulator = 0;
    var bits = 0;
    for (var i = 0; i < data.length; ++i) {
        var value = data[i];
        validate(0 <= value && (value >> from) === 0, 'Invalid value: ' + value + '.');
        accumulator = (accumulator << from) | value;
        bits += from;
        while (bits >= to) {
            bits -= to;
            result[index] = (accumulator >> bits) & mask;
            ++index;
        }
    }
    if (!strictMode) {
        if (bits > 0) {
            result[index] = (accumulator << (to - bits)) & mask;
            ++index;
        }
    } else {
        validate(
            bits < from && ((accumulator << (to - bits)) & mask) === 0,
            'Input cannot be converted to ' + to + ' bits without padding, but strict mode was used.'
        );
    }
    return result;
}

function prefixToArray(prefix) {
    const result = [];
    for (let i = 0; i < prefix.length; i++) {
        result.push(prefix.charCodeAt(i) & 31);
    }
    return result;
}

function fromHex(data) {
    if (data.startsWith("0x")) {
        data = data.substring(2)
    }
    return Buffer.from(data, "hex")
}

function encode(data) {
    const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    var base32 = '';
    for (var i = 0; i < data.length; ++i) {
        var value = data[i];
        validate(0 <= value && value < 32, 'Invalid value: ' + value + '.');
        base32 += CHARSET[value];
    }
    return base32;
}

function encodePubKeyAddress(pubKey, prefix) {
    const eight0 = [0, 0, 0, 0, 0, 0, 0, 0];
    const prefixData = prefixToArray(prefix).concat([0]);
    const versionByte = 0;

    const pubKeyArray = Array.prototype.slice.call(fromHex(pubKey), 0);
    const payloadData = convertBits(new Uint8Array([versionByte].concat(pubKeyArray)), 8, 5, false);
    const checksumData = new Uint8Array(prefixData.length + payloadData.length + eight0.length);
    checksumData.set(prefixData);
    checksumData.set(payloadData, prefixData.length);
    checksumData.set(eight0, prefixData.length + payloadData.length);
    const polymodData = checksumToArray(polymod(checksumData));

    const payload = new Uint8Array(payloadData.length + polymodData.length);
    payload.set(payloadData);
    payload.set(polymodData, payloadData.length);

    return 'kaspa:' + encode(payload);
}

async function test() {
    const mnemonic = 'reopen vivid parent want raw main filter rotate earth true fossil dream';
    const seed = await bip39.mnemonicToSeed(mnemonic);
    var hdkey = HDKey.fromMasterSeed(Buffer.from(seed, 'hex'));
    var childkey = hdkey.derive("m/44'/111111'/0'/0/0");
    // Compressed 形式，开头可能是02或者03
    const CompressedKey = childkey.publicKey.toString('hex');
    const address = encodePubKeyAddress(CompressedKey.slice(2), "kaspa");
    console.log(address);
    // kaspa:qqpet37fwqlql7q4jczr7zj7qp5ylps2r2c0ynz6jjf368sdjnztufeghvc9x
}

test()