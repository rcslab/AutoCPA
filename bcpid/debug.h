/*
 * Copyright (c) 2012-2018 Ali Mashtizadeh
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __BCPID_DEBUG_H__
#define __BCPID_DEBUG_H__

#include <assert.h>
#include <stdlib.h>

#include <unistd.h>

#include <functional>

#define LEVEL_SYS 0 /* Assert/Panic/Abort/NotImplemented */
#define LEVEL_ERR 1 /* Error */
#define LEVEL_WRN 2 /* Warning */
#define LEVEL_MSG 3 /* Stdout */
#define LEVEL_LOG 4 /* Log */
#define LEVEL_DBG 5 /* Debug */
#define LEVEL_VRB 6 /* Verbose */

/*
 * Remove all logging in PERF builds
 */
#ifdef BCPID_PERF
#define WARNING(fmt, ...)
#define MSG(fmt, ...)
#define LOG(fmt, ...)
#else
#define WARNING(fmt, ...) Debug_Log(LEVEL_WRN, fmt "\n", ##__VA_ARGS__)
#define MSG(fmt, ...) Debug_Log(LEVEL_MSG, fmt "\n", ##__VA_ARGS__)
#define LOG(fmt, ...) Debug_Log(LEVEL_LOG, fmt "\n", ##__VA_ARGS__)
#endif

#define SYSERROR(fmt, ...) Debug_Log(LEVEL_ERR, fmt "\n", ##__VA_ARGS__)
#define PERROR(str) Debug_Perror(str, errno)

/*
 * Only DEBUG builds compile in DLOG messages
 */
#ifdef BCPID_DEBUG
#define DLOG(fmt, ...) Debug_Log(LEVEL_DBG, fmt "\n", ##__VA_ARGS__)
#else
#define DLOG(fmt, ...)
#endif

#ifdef BCPID_DEBUG
#define ASSERT(_x)							\
	do {								\
		if (!(_x)) {						\
			Debug_Log(LEVEL_SYS, "ASSERT(" #_x "): %s %s:%d\n", \
				  __FUNCTION__, __FILE__, __LINE__);	\
			assert(_x);					\
		}							\
	} while (0)
#else
#define ASSERT(_x) ((void)0)
#endif

#ifdef _WIN32
#define PANIC()								\
	do {								\
		Debug_Log(LEVEL_SYS, "PANIC: function %s, file %s, line %d\n", \
			  __FUNCTION__, __FILE__, __LINE__);		\
		abort();						\
	} while (0)
#define NOT_IMPLEMENTED(_x)						\
	do {								\
		if (!(_x)) {						\
			Debug_Log(LEVEL_SYS, "NOT_IMPLEMENTED(" #_x "): %s %s:%d\n", \
				  __FUNCTION__, __FILE__, __LINE__);	\
			abort();					\
		}							\
	} while (0)
#define NOT_REACHED()							\
	do {								\
		Debug_Log(LEVEL_SYS, "NOT_REACHED: function %s, file %s, line %d\n", \
			  __FUNCTION__, __FILE__, __LINE__);		\
		abort();                               \
	} while (0)
#else /* _WIN32 */
#define PANIC()								\
	do {								\
		Debug_Log(LEVEL_SYS, "PANIC: function %s, file %s, line %d\n", \
			  __func__, __FILE__, __LINE__);		\
		abort();						\
	} while (0)
#define NOT_IMPLEMENTED(_x)						\
	do {								\
		if (!(_x)) {						\
			Debug_Log(LEVEL_SYS, "NOT_IMPLEMENTED(" #_x "): %s %s:%d\n", \
				  __func__, __FILE__, __LINE__);	\
			abort();					\
		}							\
	} while (0)
#define NOT_REACHED()							\
	do {								\
		Debug_Log(LEVEL_SYS, "NOT_REACHED: function %s, file %s, line %d\n", \
			  __FUNCTION__, __FILE__, __LINE__);		\
		abort();						\
		__builtin_unreachable();				\
	} while (0)
#endif /* _WIN32 */

int Debug_OpenLog(const std::string &logPath);
void Debug_Log(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void Debug_Perror(const char *fmt, int err);
void Debug_PrintHex(const std::string &data, off_t off = 0, size_t limit = 0);
void Debug_PrintBacktrace();
void Debug_LogBacktrace();

void Debug_AddOutput(void *handle, std::function<void(const std::string &)> func);
void Debug_RemoveOutput(void *handle);

#endif /* __BCPID_DEBUG_H__ */
