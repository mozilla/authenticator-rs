/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __U2FHID_CAPI
#define __U2FHID_CAPI
#include <stdlib.h>
#include "nsString.h"

extern "C" {

// NOTE: Preconditions
// * All rust_u2f_mgr* pointers must refer to pointers which are returned
//   by rust_u2f_mgr_new, and must be freed with rust_u2f_mgr_free.

// The `rust_u2f_mgr` opaque type is equivalent to the rust type `::manager::U2FManager`
struct rust_u2f_mgr;

rust_u2f_mgr* rust_u2f_mgr_new();
/* unsafe */ void rust_u2f_mgr_free(rust_u2f_mgr* mgr);

void rust_u2f_mgr_register(rust_u2f_mgr* mgr, uint64_t timeout,
                           const uint8_t* challenge_ptr, size_t challenge_len,
                           const uint8_t* application_ptr, size_t application_len,
                           uint8_t* registration_ptr, size_t* registration_len, size_t max_registration_len);

void rust_u2f_mgr_sign(rust_u2f_mgr* mgr, uint64_t timeout,
                       const uint8_t* challenge_ptr, size_t challenge_len,
                       const uint8_t* application_ptr, size_t application_len,
                       const uint8_t* key_handle_ptr, size_t key_handle_len,
                       uint8_t* signature_ptr, size_t* signature_len, size_t max_signature_len);

}

#endif // __U2FHID_CAPI
