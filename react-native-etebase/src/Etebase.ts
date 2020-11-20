// Shim document if it doesn't exist (e.g. on React native)
if ((typeof global !== "undefined") && !(global as any).document) {
    (global as any).document = {};
}

import "react-native-get-random-values";
import RnSodium from "react-native-sodium";
import sodium from 'libsodium-wrappers';

import { _setDeriveKeyImplementation } from "etebase"

_setDeriveKeyImplementation(async function (salt: Uint8Array, password: string) {
    const ret = await RnSodium.crypto_pwhash(
        32,
        sodium.to_base64(sodium.from_string(password), sodium.base64_variants.ORIGINAL),
        sodium.to_base64(salt, sodium.base64_variants.ORIGINAL),
        sodium.crypto_pwhash_OPSLIMIT_SENSITIVE,
        sodium.crypto_pwhash_MEMLIMIT_MODERATE,
        sodium.crypto_pwhash_ALG_DEFAULT,
    )

    return sodium.from_base64(ret, sodium.base64_variants.ORIGINAL)
})

export * from "etebase";
