"use strict"

const re_nonce = /^[A-Za-z0-9\-_=]+$/

function amIAdmin(privateKey, myFingerprint, onAnswer, onClose, onError) {
    websocketApi(privateKey, "user/" + myFingerprint,
        answer => onAnswer(answer !== null && answer.access_level === ADMIN_ACCESS),
        onClose,
        onError)
}

function deleteKeys(privateKey, onDelete, onError) {
    const deleteCb = () => {
        localStorage.removeItem("my_keys")
        onDelete()
    }

    if (!isMyKeyOnserver()) {
        deleteCb()
    } else {
        websocketApi(privateKey, "key/delete",
            () => {},
            deleteCb,
            onError
        )
    }
}

function getAllUser(privateKey, onAnswer, onClose, onError) {
    websocketApi(privateKey, "user/all", onAnswer, onClose, onError)
}

function getCollectedData(privateKey, formName, onAnswer, onClose, onError) {
    websocketApi(privateKey, "data/get/" + formName, onAnswer, onClose, onError)
}

function getFormKeysFingerprints(privateKey, formId, onAnswer, onClose, onError) {
    websocketApi(privateKey, "form/get/" + formId, onAnswer, onClose, onError)
}

async function getPrivateKey(password) {
    const { keys: [myKey] } = await openpgp.key.readArmored(loadMyKeys().priv)
    if (password !== null && password.length)
        await myKey.decrypt(password)
    return myKey
}

async function initKeys(passphrase) {
    let kp
    if (passphrase.length) {
        kp = await openpgp.generateKey({
            userIds: [{}],
            curve: "ed25519",
            passphrase,
        })
    } else {
        kp = await openpgp.generateKey({
            userIds: [{}],
            curve: "ed25519",
        })
    }

    const myKeys = {
        priv: kp.privateKeyArmored,
        pub: kp.publicKeyArmored,
        id: kp.key.getFingerprint(),
    }

    localStorage.setItem("my_keys", JSON.stringify(myKeys))

    return kp
}

async function isMyKeyOnserver() {
    const response = await fetch(FETCH_PROTOCOL + "://" + SRV + "/key/" + loadMyKeys().id)
    if (response.ok) {
        const key = await response.text()
        if (key === "Unknown") {
            return false
        } else {
            return true
        }
    } else {
        throw new Error("Error while checking for key on server.")
    }
}

function loadMyKeys() {
    return JSON.parse(localStorage.getItem("my_keys"))
}

async function loadSrvKey() {
    let key = null
    const response = await fetch(FETCH_PROTOCOL + "://" + SRV + "/key/srv")
    if (response.ok) {
        key = await response.text()
    } else {
        throw new Error("Error while fetching server key.")
    }
    return key
}

function setCollectedData(privateKey, formName, data, onClose, onError) {
    websocketApi(privateKey, "data/set/" + formName, answer => answer, onClose, onError, data)
}

function setFormKeysFingerprints(privateKey, formName, fingerprints, onClose, onError) {
    websocketApi(privateKey, "form/set/" + formName, answer => answer, onClose, onError, { fingerprints })
}

async function submitPubKey() {
    const body = JSON.stringify({
        pubKey: loadMyKeys().pub
    })
    const res = await fetch(FETCH_PROTOCOL + "://" + SRV + "/key/add", {
        method: "POST",
        body,
    })
}

async function websocketApi(privateKey, request, onAnswer, onClose, onError, payload=null) {
    const srvKey = await loadSrvKey()
    const message = JSON.stringify({ request, payload })
    let encrypted_request
    try {
        encrypted_request = (await openpgp.encrypt({
            message: openpgp.message.fromText(message),
            publicKeys: (await openpgp.key.readArmored(srvKey)).keys,
            privateKeys: privateKey
        })).data
    } catch (error) {
        onError(error.message)
        return
    }

    const ws = new WebSocket("ws://" + SRV, "pgp-json")
    ws.onmessage = async message => {
        const decrypted = await openpgp.decrypt({
            message: await openpgp.message.readArmored(message.data),
            publicKeys: (await openpgp.key.readArmored(srvKey)).keys,
            privateKeys: privateKey
        })
        if (decrypted.signatures[0].valid) {
            const message = JSON.parse(decrypted.data)
            if (message.request === request) {
                if (typeof message.nonce === "string" && re_nonce.test(message.nonce)) {
                    const { data: signature_response } = await openpgp.encrypt({
                        message: await openpgp.message.fromText(decrypted.data),
                        publicKeys: (await openpgp.key.readArmored(srvKey)).keys,
                        privateKeys: privateKey
                    })
                    ws.send(signature_response)
                } else if (typeof message.payload === "object") {
                    onAnswer(message.payload)
                    ws.close(1000)
                } else {
                    ws.close(1002, "Unsupported message type")
                    onError("Received uknown message type: " + JSON.stringify(message))
                }
            } else {
                ws.close(1008, "Wrong request.")
                onError("Received packet for request " + message.request + ". " +
                        "But we are asking for " + request + ".")
            }
        } else {
            ws.close(1008, "Invalid signature.")
            onError("Invalid signature from server.")
        }
    }
    ws.onclose = close => {
        if (close.code !== 1000) {
            onError("connection closed with code: " +  close.code +
                    ", reason: " + close.reason)
        } else {
            onClose()
        }
    }
    ws.onopen = event => {
        ws.send(encrypted_request)
    }
}
