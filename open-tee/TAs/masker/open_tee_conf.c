#ifdef TA_PLUGIN

/* This is the required functionality to enable running the TA in OpenTee.  Make sure to update
   the UUID to your own unique ID. */
#include "tee_ta_properties.h"

SET_TA_PROPERTIES(
    { 0x12345678, 0x8765, 0x4321, { 'M', 'A', 'S', 'C', '0', '0', '0', '2'} }, 512, 255, 1, 1, 1)
#endif
