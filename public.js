"use strict"

async function getFormKeys(formName) {
    const response = await fetch(FETCH_PROTOCOL + "://" + SRV + "/formkeys/" + formName)
    if (response.ok) {
        const keys = (await response.json()).keys
        if (keys.length === 0)
            throw new Error("No key set for this form.")
        return keys
    } else {
        throw new Error("Error occured while fetching form keys.")
    }
}

async function postFormSecret(formName, secret) {
    const armoredKeys = await getFormKeys(formName)
    const publicKeys = await Promise.all(armoredKeys.map(async key => (await openpgp.key.readArmored(key)).keys[0]))
    const { data: encryptedSecret } = await openpgp.encrypt({
        message: openpgp.message.fromText(secret),
        publicKeys
    })

    const response = await fetch(FETCH_PROTOCOL + "://" + SRV + "/post/" + formName, {
        method: "POST",
        body: encryptedSecret
    })
    if (!response.ok)
        throw new Error("Error occured while posting form.")
}
