#ifndef NETFUZZLIB_LOG_H
#define NETFUZZLIB_LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

enum { NETFUZZLIB_LOG_TRACE, NETFUZZLIB_LOG_DEBUG, NETFUZZLIB_LOG_INFO, NETFUZZLIB_LOG_WARN, NETFUZZLIB_LOG_ERROR, NETFUZZLIB_LOG_FATAL };

#ifdef NFL_DEBUG
#define nfl_log_trace(...) nfl_log_log(NETFUZZLIB_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define nfl_log_debug(...) nfl_log_log(NETFUZZLIB_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define nfl_log_info(...) nfl_log_log(NETFUZZLIB_LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define nfl_log_warn(...) nfl_log_log(NETFUZZLIB_LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define nfl_log_error(...) nfl_log_log(NETFUZZLIB_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define nfl_log_fatal(...) nfl_log_log(NETFUZZLIB_LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)
#else
#define nfl_log_trace(...)
#define nfl_log_debug(...)
#define nfl_log_info(...)
#define nfl_log_warn(...)
#define nfl_log_error(...)
#define nfl_log_fatal(...)
#endif

void nfl_log_log(int level, const char *file, int line, const char *fmt, ...);

void nfl_init_logging(char *logfile_path);

#endif //NETFUZZLIB_LOG_H
