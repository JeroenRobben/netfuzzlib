#pragma once

/*
 * Build-time mode detection. The same test sources compile into two binaries:
 *   tests_native runs against the real Linux kernel (libc only)
 *   tests_nfl    links libnfl statically, calls go through the model
 *
 * One of NFL_TEST_NATIVE_MODE / NFL_TEST_NFL_MODE is defined by CMake.
 *
 * Use kIsNfl / kIsNative to branch in test code, and SKIP_IF_NATIVE() /
 * SKIP_IF_NFL() to opt a test out of one mode entirely.
 */

#if defined(NFL_TEST_NFL_MODE)
constexpr bool kIsNfl = true;
constexpr bool kIsNative = false;
#elif defined(NFL_TEST_NATIVE_MODE)
constexpr bool kIsNfl = false;
constexpr bool kIsNative = true;
#else
#error "Exactly one of NFL_TEST_NATIVE_MODE or NFL_TEST_NFL_MODE must be defined"
#endif

#define SKIP_IF_NATIVE() \
    do { if (kIsNative) GTEST_SKIP() << "skipped in native mode"; } while (0)

#define SKIP_IF_NFL() \
    do { if (kIsNfl) GTEST_SKIP() << "skipped in nfl mode"; } while (0)
