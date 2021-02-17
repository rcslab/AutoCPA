#pragma once

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)

extern "C" {

#endif

uint32_t bcpi_crc32(const void *buf, size_t size);

#if defined(__cplusplus)
}

#endif
