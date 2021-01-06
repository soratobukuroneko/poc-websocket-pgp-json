"use strict"

const re_nonce = /^[A-Za-z0-9\-_=]+$/

function amIAdmin(password, myFingerprint, onAnswer, onClose, onError) {
    websocketApi(password, "user/" + myFingerprint,
        answer => onAnswer(answer !== null && answer.access_level === ADMIN_ACCESS),
        onClose,
        onError)
}

function deleteKeys(password, onDelete, onError) {
    const deleteCb = () => {
        localStorage.removeItem("my_keys")
        onDelete()
    }

    if (!isMyKeyOnserver()) {
        deleteCb()
    } else {
        websocketApi(password, "key/delete",
            () => {},
            deleteCb,
            onError
        )
    }
}

function getAllUser(password, onAnswer, onClose, onError) {
    websocketApi(password, "user/all", onAnswer, onClose, onError)
}

function getCollectedData(password, formName, onAnswer, onClose, onError) {
    websocketApi(password, "data/get/" + formName, onAnswer, onClose, onError)
}

function getFormKeysFingerprints(password, formId, onAnswer, onClose, onError) {
    websocketApi(password, "form/get/" + formId, onAnswer, onClose, onError)
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

    return myKeys
}

async function isMyKeyOnserver() {
    const res = await fetch(FETCH_PROTOCOL + "://" + SRV + "/key/" + loadMyKeys().id)
    if (res.ok) {
        const key = await res.text()
        if (key === "Unknown") {
            return false
        } else {
            return true
        }
    } else {
        throw Error("Error while checking for key on server.")
    }
}

function loadMyKeys() {
    return JSON.parse(localStorage.getItem("my_keys"))
}

async function loadSrvKey() {
    let key = sessionStorage.getItem("srv_key")
    if (key === null) {
        const res = await fetch(FETCH_PROTOCOL + "://" + SRV + "/key/srv")
        if (res.ok) {
            key = await res.text()
            sessionStorage.setItem("srv_key", key)
        } else {
            throw Error("Error while fetching server key.")
        }
    }

    return key
}

function setFormKeysFingerprints(password, formName, fingerprints, onClose, onError) {
    websocketApi(password, "form/set/" + formName, answer => answer, onClose, onError, { fingerprints })
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

async function websocketApi(password, request, onAnswer, onClose, onError, payload=null) {
    const srvKey = await loadSrvKey()
    const { keys: [myKey] } = await openpgp.key.readArmored(loadMyKeys().priv)
    if (password !== null && password.length)
        await myKey.decrypt(password)
    const message = JSON.stringify({ request, payload })
    const { data: encrypted_request } = await openpgp.encrypt({
        message: openpgp.message.fromText(message),
        publicKeys: (await openpgp.key.readArmored(srvKey)).keys,
        privateKeys: [myKey]
    })
    const ws = new WebSocket("ws://" + SRV, "pgp-json")
    ws.onmessage = async message => {
        const decrypted = await openpgp.decrypt({
            message: await openpgp.message.readArmored(message.data),
            publicKeys: (await openpgp.key.readArmored(srvKey)).keys,
            privateKeys: [myKey]
        })
        if (decrypted.signatures[0].valid) {
            const message = JSON.parse(decrypted.data)
            if (message.request === request) {
                if (typeof message.nonce === "string" && re_nonce.test(message.nonce)) {
                    const { data: signature_response } = await openpgp.encrypt({
                        message: await openpgp.message.fromText(decrypted.data),
                        publicKeys: (await openpgp.key.readArmored(srvKey)).keys,
                        privateKeys: [myKey]
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
