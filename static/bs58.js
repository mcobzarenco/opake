// Base58 encoding/decoding
// Originally written by Mike Hearn for BitcoinJ
// Copyright (c) 2011 Google Inc
// Ported to JavaScript by Stefan Thomas
// Merged Buffer refactorings from base58-native by Stephen Pair
// Copyright (c) 2013 BitPay Inc

var BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
var BASE58_ALPHABET_MAP = {}
for(var i = 0; i < BASE58_ALPHABET.length; i++) {
  BASE58_ALPHABET_MAP[BASE58_ALPHABET.charAt(i)] = i
}
var BASE58 = 58

function b58encode(buffer) {
  if (buffer.length === 0) return ''

  var i, j, digits = [0]
  for (i = 0; i < buffer.length; i++) {
    for (j = 0; j < digits.length; j++) digits[j] <<= 8

    digits[0] += buffer[i]

    var carry = 0
    for (j = 0; j < digits.length; ++j) {
      digits[j] += carry

      carry = (digits[j] / BASE58) | 0
      digits[j] %= BASE58
    }

    while (carry) {
      digits.push(carry % BASE58)

      carry = (carry / BASE58) | 0
    }
  }

  // deal with leading zeros
  for (i = 0; i < buffer.length - 1 && buffer[i] == 0; i++) digits.push(0)

  return digits.reverse().map(function(digit) { return BASE58_ALPHABET[digit] }).join('')
}

function b58decode(string) {
  if (string.length === 0) {
      return new Uint8Array(0);
  }

  var input = string.split('').map(function(c){
    if (!(c in BASE58_ALPHABET_MAP)) {
        throw('Non-base58 character');
    }
    return BASE58_ALPHABET_MAP[c];
  })

  var i, j, bytes = [0]
  for (i = 0; i < input.length; i++) {
    for (j = 0; j < bytes.length; j++) bytes[j] *= BASE58
    bytes[0] += input[i]

    var carry = 0
    for (j = 0; j < bytes.length; ++j) {
      bytes[j] += carry

      carry = bytes[j] >> 8
      bytes[j] &= 0xff
    }

    while (carry) {
      bytes.push(carry & 0xff)

      carry >>= 8
    }
  }

  // deal with leading zeros
  for (i = 0; i < input.length - 1 && input[i] == 0; i++) bytes.push(0)

  return new Uint8Array(bytes.reverse())
}
