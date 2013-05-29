#ifndef DEBUG_H
#define DEBUG_H

#define DEBUG			1

#if DEBUG == 1
#define DbgPrint(mesg, ...)	fprintf(stderr, mesg, __VA_ARGS__)
#else
#define DbgPrint(mesg, ...)
#endif

#define XHIDS_DEBUG(fp, func, fmt, ...) \
			xhids_debug(fp, __FILE__, __LINE__, func, fmt, __VA_ARGS__)

void xhids_debug(FILE *fp, const char *file_name, int line, const char *func_name,
                const char *fmt, ...);

#endif
