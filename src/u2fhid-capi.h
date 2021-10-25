/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __U2FHID_CAPI
#define __U2FHID_CAPI
#include <stdlib.h>
#include "nsString.h"

extern "C" {

extern uint8_t U2F_RESBUF_ID_REGISTRATION;
extern uint8_t U2F_RESBUF_ID_KEYHANDLE;
extern uint8_t U2F_RESBUF_ID_SIGNATURE;
extern uint8_t U2F_RESBUF_ID_APPID;
extern uint8_t U2F_RESBUF_ID_VENDOR_NAME;
extern uint8_t U2F_RESBUF_ID_DEVICE_NAME;
extern uint8_t U2F_RESBUF_ID_FIRMWARE_MAJOR;
extern uint8_t U2F_RESBUF_ID_FIRMWARE_MINOR;
extern uint8_t U2F_RESBUF_ID_FIRMWARE_BUILD;
extern uint8_t CTAP2_RESBUF_ID_CTAP20_INDICATOR;
extern uint8_t CTAP2_RESBUF_ID_ATTESTATION_STATEMENT_ALGORITHM;
extern uint8_t CTAP2_RESBUF_ID_ATTESTATION_STATEMENT_SIGNATURE;
extern uint8_t CTAP2_RESBUF_ID_ATTESTATION_STATEMENT_CERTIFICATE;
extern uint8_t CTAP2_RESBUF_ID_ATTESTATION_STATEMENT_UNPARSED;
extern uint8_t CTAP2_RESBUF_ID_AUTHENTICATOR_DATA;
extern uint8_t CTAP2_RESBUF_ID_CLIENT_DATA;

const uint64_t U2F_FLAG_REQUIRE_RESIDENT_KEY = 1;
const uint64_t U2F_FLAG_REQUIRE_USER_VERIFICATION = 2;
const uint64_t U2F_FLAG_REQUIRE_PLATFORM_ATTACHMENT = 4;

const uint8_t U2F_AUTHENTICATOR_TRANSPORT_USB = 1;
const uint8_t U2F_AUTHENTICATOR_TRANSPORT_NFC = 2;
const uint8_t U2F_AUTHENTICATOR_TRANSPORT_BLE = 4;
const uint8_t CTAP_AUTHENTICATOR_TRANSPORT_INTERNAL = 8;

extern uint8_t U2F_ERROR_UKNOWN;
extern uint8_t U2F_ERROR_NOT_SUPPORTED;
extern uint8_t U2F_ERROR_INVALID_STATE;
extern uint8_t U2F_ERROR_CONSTRAINT;
extern uint8_t U2F_ERROR_NOT_ALLOWED;
extern uint8_t CTAP_ERROR_PIN_REQUIRED;
extern uint8_t CTAP_ERROR_PIN_INVALID;
extern uint8_t CTAP_ERROR_PIN_AUTH_BLOCKED;
extern uint8_t CTAP_ERROR_PIN_BLOCKED;

// NOTE: Preconditions
// * All rust_u2f_mgr* pointers must refer to pointers which are returned
//   by rust_u2f_mgr_new, and must be freed with rust_u2f_mgr_free.
// * All rust_u2f_khs* pointers must refer to pointers which are returned
//   by rust_u2f_khs_new, and must be freed with rust_u2f_khs_free.
// * All rust_u2f_res* pointers must refer to pointers passed to the
//   register() and sign() callbacks. They can be null on failure.

// The `rust_u2f_mgr` opaque type is equivalent to the rust type `U2FManager`
// TODO(MS): Once CTAP2 support is added, this should probably be renamed.
struct rust_u2f_manager;

// The `rust_u2f_app_ids` opaque type is equivalent to the rust type `U2FAppIds`
struct rust_u2f_app_ids;

// The `rust_u2f_key_handles` opaque type is equivalent to the rust type
// `U2FKeyHandles`
struct rust_u2f_key_handles;

// The `rust_u2f_res` opaque type is equivalent to the rust type `U2FResult`
struct rust_u2f_result;

// The callback passed to register() and sign().
typedef void (*rust_u2f_callback)(uint64_t, rust_u2f_result*);

/// CTAP2 functions
rust_u2f_manager* rust_ctap2_mgr_new();

/// U2FManager functions.

rust_u2f_manager* rust_u2f_mgr_new();
/* unsafe */ void rust_u2f_mgr_free(rust_u2f_manager* mgr);

uint64_t rust_u2f_mgr_register(rust_u2f_manager* mgr, uint64_t flags,
                               uint64_t timeout, rust_u2f_callback,
                               const uint8_t* challenge_ptr,
                               size_t challenge_len,
                               const uint8_t* application_ptr,
                               size_t application_len,
                               const rust_u2f_key_handles* khs);

uint64_t rust_u2f_mgr_sign(rust_u2f_manager* mgr, uint64_t flags,
                           uint64_t timeout, rust_u2f_callback,
                           const uint8_t* challenge_ptr, size_t challenge_len,
                           const rust_u2f_app_ids* app_ids,
                           const rust_u2f_key_handles* khs);

void rust_u2f_mgr_cancel(rust_u2f_manager* mgr);

/// U2FAppIds functions.

rust_u2f_app_ids* rust_u2f_app_ids_new();
void rust_u2f_app_ids_add(rust_u2f_app_ids* ids, const uint8_t* id,
                          size_t id_len);
/* unsafe */ void rust_u2f_app_ids_free(rust_u2f_app_ids* ids);

/// U2FKeyHandles functions.

rust_u2f_key_handles* rust_u2f_khs_new();
void rust_u2f_khs_add(rust_u2f_key_handles* khs, const uint8_t* key_handle,
                      size_t key_handle_len, uint8_t transports);
/* unsafe */ void rust_u2f_khs_free(rust_u2f_key_handles* khs);

/// U2FResult functions.

// Returns 0 for success, or the U2F_ERROR error code >= 1.
uint8_t rust_u2f_result_error(const rust_u2f_result* res);

// Call this before `[..]_copy()` to allocate enough space.
bool rust_u2f_resbuf_length(const rust_u2f_result* res, uint8_t bid,
                            size_t* len);
bool rust_u2f_resbuf_contains(const rust_u2f_result* res, uint8_t bid);
bool rust_u2f_resbuf_copy(const rust_u2f_result* res, uint8_t bid,
                          uint8_t* dst);
/* unsafe */ void rust_u2f_res_free(rust_u2f_result* res);

/// CTAP2 functions.
uint64_t rust_ctap2_mgr_register(
    rust_u2f_manager* mgr, uint64_t timeout, rust_u2f_callback,
    const uint8_t* challenge_ptr, size_t challenge_len,
    const char* relying_party_id, const char *origin_ptr,
    const uint8_t *user_id_ptr, size_t user_id_len,
    const char *user_name, const int32_t *pub_cred_params_ptr,
    size_t pub_cred_params_len, const rust_u2f_key_handles* exclude_list,
    const char *pin
);

uint64_t rust_ctap2_mgr_sign(
    rust_u2f_manager* mgr, uint64_t timeout, rust_u2f_callback,
    uint64_t flags, const uint8_t* challenge_ptr, size_t challenge_len,
    const char* relying_party_id, const char *origin_ptr,
    const rust_u2f_key_handles* allow_list,
    const char *pin
);
}

#endif  // __U2FHID_CAPI
