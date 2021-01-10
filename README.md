# PoC WebSocket PGP JSON

This PoC shows a way to encrypt e2e data collected from forms for one or more users using PGP

## Requirements

* Recent Python 3
* Python 3 binding for GPGME (python3-gpg)
* OpenPGP.js (openpgp.min.js)

## Run

`./server.py [port] [listen address] [datadir]`

* default port: `8000`
* default listen address: `127.0.0.1`
* default data directory: random temporary one and in memory database

If you are running the server on a different address/port than the default one, you have to edit [config.js](config.js) `SRV` constant.

Once the server is running you can browse:

1. Server root (`/`) to generate user keys and upload the public key to the server. First one is admin.
1. `/admin.html` to set forms keys for encryption and reencrypt data after keys change.
1. `/forms.html` to collect data.
1. `/data.html` to view collected data.

## Protocol brief overview

### API request from registered users

1. Client fetch the server public key (for this particular step we assume the link is secure)
1. Client encrypt with server key and sign with its own key a JSON of the format `{ request: "api/request", payload: "optional payload" }`
   and send it over WebSocket
1. Server checks if it knows the client key. Then answer with the same JSON with an added random nonce encrypted for client and signed.
1. Client checks if the JSON request field is the same and server signature is valid (TODO check payload).
   Then sign and encrypt the message with the nonce and send it back to the server.
1. Server checks if the nonce is the same and the signature from the client is valid and recent enough and then execute the request
   and answer it if needed and close the connection.

### Public request

Simply done over basic HTTP with fetch. Again we trust that the link is secure
