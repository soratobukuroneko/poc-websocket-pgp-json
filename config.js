"use strict"

const SRV = "127.0.0.1:8000"
// As we expect that the public keys are fetched on a secure connection,
// http should only be concidered if tunneled by ssh or something like
// this.
const FETCH_PROTOCOL =  "http"

// Must match the value in server.py
const ADMIN_ACCESS = 100
