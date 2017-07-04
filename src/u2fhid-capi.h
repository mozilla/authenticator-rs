/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __U2FHID_CAPI
#define __U2FHID_CAPI
#include <stdlib.h>
#include "nsString.h"

extern "C" {

const uint8_t U2F_RESBUF_ID_REGISTRATION = 0;
const uint8_t U2F_RESBUF_ID_KEYHANDLE = 1;
const uint8_t U2F_RESBUF_ID_SIGNATURE = 2;

// NOTE: Preconditions
// * All rust_u2f_mgr* pointers must refer to pointers which are returned
//   by rust_u2f_mgr_new, and must be freed with rust_u2f_mgr_free.
// * All rust_u2f_res* pointers must refer to pointers passed to the
//   register() and sign() callbacks. They can be null on failure.

// The `rust_u2f_mgr` opaque type is equivalent to the rust type `U2FManager`
struct rust_u2f_mgr;

// The `rust_u2f_res` opaque type is equivalent to the rust type `U2FResult`
struct rust_u2f_res;

rust_u2f_mgr* rust_u2f_mgr_new();
/* unsafe */ void rust_u2f_mgr_free(rust_u2f_mgr* mgr);
/* unsafe */ void rust_u2f_res_free(rust_u2f_res* res);

// Call this before `[..]_copy()` to allocate enough space.
bool rust_u2f_resbuf_length(const rust_u2f_res *res, uint8_t bid, size_t* len);
bool rust_u2f_resbuf_copy(const rust_u2f_res *res, uint8_t bid, uint8_t* dst);

bool rust_u2f_mgr_register(rust_u2f_mgr* mgr, uint64_t tid, uint64_t timeout,
                           void (*callback)(uint64_t, rust_u2f_res*),
                           const uint8_t* challenge_ptr, size_t challenge_len,
                           const uint8_t* application_ptr, size_t application_len);

bool rust_u2f_mgr_sign(rust_u2f_mgr* mgr, uint64_t tid, uint64_t timeout,
                       void (*callback)(uint64_t, rust_u2f_res*),
                       const uint8_t* challenge_ptr, size_t challenge_len,
                       const uint8_t* application_ptr, size_t application_len,
                       const uint8_t* key_handle_ptr, size_t key_handle_len);

void rust_u2f_mgr_cancel(rust_u2f_mgr* mgr);

}

#endif // __U2FHID_CAPI
