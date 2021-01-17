"use strict"

const SRV = document.location.host
// As we expect that the public keys are fetched on a secure connection,
// http should only be concidered if tunneled by ssh or something like
// this.
const FETCH_PROTOCOL =  "http"

// Must match the value in server.py
const ADMIN_ACCESS = 100

const formNames = ["text_field_form", "other_form"]
