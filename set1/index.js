const convertHexToBase64 = (hex) => {
    // convert to binary
    const binary = Buffer.from(hex, 'hex').toString('binary')
    console.log('here is binary')
    console.log(binary)
    // convert binary to base64
    const base64 = btoa(binary)
    return base64
}

const convertHexToUTF8 = (hex) => {
    const utf8 = Buffer.from(hex, 'hex').toString('utf8')
    return utf8
}

const fixedXor = (xor1, xor2) => {
    const string1 = convertHexToUTF8(xor1)
    const string2 = convertHexToUTF8(xor2)
    console.log('here is string1')
    console.log(string1)

    let result = Buffer.alloc(string1.length);

    for (let i = 0; i < string1.length; i++) {
        result[i] = string1[i] ^ string2[i];
    }

    return result;
}

console.log('problem 1')
const string1 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
console.log('len')
console.log(string1.length)
console.log(convertHexToBase64(string1))

console.log('problem 2')
const xor1 = '1c0111001f010100061a024b53535009181c'
const xor2 = '686974207468652062756c6c277320657965'
console.log(fixedXor(xor1, xor2))

