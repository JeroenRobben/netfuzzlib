# module-test: linked into the gtest binary tests_nfl. Publishes a
# deterministic interface set so unit tests have a known ground truth.
nfl_add_dual_library(module-test SOURCES module-test.c)

# module-test-scripted: LD_PRELOAD'd alongside libnfl for the
# integration program tests. Replays a scenario file and asserts the
# program's outbound traffic matches.
add_library(module-test-scripted SHARED module-test-scripted.c)
target_link_libraries(module-test-scripted PRIVATE netfuzzlib_headers)
set_target_properties(module-test-scripted PROPERTIES POSITION_INDEPENDENT_CODE ON)

# module-bridge-kernel: LD_PRELOAD'd alongside libnfl for the
# docker-isolated daemon integration tests. Mirrors nfl sockets onto
# real kernel sockets so unmodified third-party clients (curl, dig, …)
# can drive the daemon over the loopback interface.
nfl_add_dual_library(module-bridge-kernel SOURCES module-bridge-kernel.c)

# module-replay: LD_PRELOAD'd alongside libnfl to stream a
# prerecorded byte transcript (NFL_REPLAY_TRANSCRIPT) to a client target
# with no live peer. Used by the ssh-keyscan integration test to feed
# it a recorded SSH server handshake deterministically.
nfl_add_dual_library(module-replay SOURCES module-replay.c)

