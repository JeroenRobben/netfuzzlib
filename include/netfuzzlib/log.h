#ifndef NETFUZZLIB_LOG_H
#define NETFUZZLIB_LOG_H

__attribute__((noreturn, format(printf, 4, 5))) void nfl_log_die(int exit_code, const char *file, int line, const char *fmt, ...);
#define nfl_die(code, ...) nfl_log_die((code), __FILE__, __LINE__, __VA_ARGS__)

#ifdef NFL_DEBUG
void nfl_init_logging(const char *logfile_path);

__attribute__((format(printf, 3, 4))) void nfl_log_impl(const char *file, int line, const char *fmt, ...);

#define nfl_log(...) nfl_log_impl(__FILE__, __LINE__, __VA_ARGS__)
#else
#define nfl_init_logging(logfile_path) ((void)0)
#define nfl_log(...) ((void)0)
#endif

#endif // NETFUZZLIB_LOG_H
