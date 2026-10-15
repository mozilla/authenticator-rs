/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include<sys/ioctl.h>
#include<linux/hidraw.h>

/* we define these constants to work around the fact that bindgen
   can't deal with the _IOR macro function. We let cpp deal with it
   for us. */

const __u32 _HIDIOCGRDESCSIZE = HIDIOCGRDESCSIZE;
#undef HIDIOCGRDESCSIZE

const __u32 _HIDIOCGRDESC = HIDIOCGRDESC;
#undef HIDIOCGRDESC
