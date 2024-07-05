#ifndef NETFUZZLIB_SOCKOPT_H
#define NETFUZZLIB_SOCKOPT_H

//Print an error message for a getsockopt call with given level and option_name
void getsockopt_print_unsupported_error(int level, int option_name);

//Print an error message for a setsockopt call with given level and option_name
void setsockopt_print_unsupported_error(int level, int option_name);

#endif // NETFUZZLIB_SOCKOPT_H
