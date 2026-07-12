#ifndef NETFUZZLIB_API_H
#define NETFUZZLIB_API_H

#include <netfuzzlib/log.h>
#include <netfuzzlib/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Allocate a packet with a buffer of len bytes for nfl_receive() to fill.
nfl_pkt *nfl_alloc_pkt(size_t len);

// Set how many consecutive idle read/poll calls on one socket the
// framework allows before calling nfl_socket_idle(). A blocking read
// calls it immediately. 0 disables calling nfl_socket_idle().
void nfl_set_max_idle_polls(int max_idle_polls);

// Preclaim `count` fd's from the kernel.
// By default, every fd is reserved lazily (by openinng a fd to /dev/null).
// If you're using a forking symbolic executor, you might want to call
// nfl_reserve_fd_poll(100) from nfl_setup(), so no fd is opened once
// execution branches.
void nfl_reserve_fd_pool(int count);

// True when no modelled socket *in this process* has any queued data 
bool nfl_all_sockets_in_process_idle(void);

#endif // NETFUZZLIB_API_H
