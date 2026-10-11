# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.25)
project(libbpf_mojo C)

set(LMB_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(LMB_SANITIZE "Build with AddressSanitizer and UBSan" OFF)

# Systems interfaces used: syscall(2), epoll, BPF UAPI.
add_compile_definitions(_GNU_SOURCE)
add_compile_options(-Wall -Wextra -Werror)
if(LMB_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

# libbpf is a build input, not a system dependency: fetch the pinned
# source tarball with hash verification and build it from source.
include(ExternalProject)
set(LIBBPF_URL "https://github.com/libbpf/libbpf/archive/refs/tags/v1.7.0.tar.gz")
set(LIBBPF_SHA256 "7ab5feffbf78557f626f2e3e3204788528394494715a30fc2070fcddc2051b7b")
set(LIBBPF_BUILD_FLAGS "-g -O2 -Werror -Wall -std=gnu89 -fPIC")
if(LMB_SANITIZE)
  string(APPEND LIBBPF_BUILD_FLAGS " -fsanitize=address,undefined -fno-omit-frame-pointer")
endif()
ExternalProject_Add(libbpf_external
  URL ${LIBBPF_URL}
  URL_HASH SHA256=${LIBBPF_SHA256}
  CONFIGURE_COMMAND ""
  # Static objects link into our shared library, so they need -fPIC.
  BUILD_COMMAND ${CMAKE_COMMAND} -E env
    "CFLAGS=${LIBBPF_BUILD_FLAGS}"
    make -C <SOURCE_DIR>/src -j
  INSTALL_COMMAND make -C <SOURCE_DIR>/src install PREFIX=<BINARY_DIR>/root
  BUILD_IN_SOURCE TRUE
)
ExternalProject_Add_Step(libbpf_external normalize
  COMMAND sh -c "cp <BINARY_DIR>/root/lib*/libbpf.a <BINARY_DIR>/libbpf.a"
  DEPENDEES install
  BYPRODUCTS <BINARY_DIR>/libbpf.a
)
ExternalProject_Get_Property(libbpf_external BINARY_DIR)
set(LIBBPF_ROOT ${BINARY_DIR}/root)
set(LIBBPF_A ${BINARY_DIR}/libbpf.a)

add_library(libbpf_static STATIC IMPORTED GLOBAL)
set_target_properties(libbpf_static PROPERTIES
  IMPORTED_LOCATION ${LIBBPF_A})
add_dependencies(libbpf_static libbpf_external)

# The native build needs ELF and zlib development files; fail closed
# with a clear message when they are absent.
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBELF REQUIRED libelf)
pkg_check_modules(ZLIB REQUIRED zlib)

set(LMB_SOURCES
  src/session.c
  src/attach.c
  src/ring.c
  src/errors.c
  src/object.c
  src/object_maps.c
)

# Product shared library. SONAME carries ABI major 1. Only the eleven
# original operations and implemented additive lmb_* operations are
# exported; the bundled libbpf and all
# bridge internals stay local (also defeating PLT interposition).
add_library(lmb SHARED ${LMB_SOURCES})
set_target_properties(lmb PROPERTIES
  OUTPUT_NAME bpf_mojo
  VERSION 1
  SOVERSION 1
  LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libbpf_mojo.map)
target_link_options(lmb PRIVATE
  "LINKER:--version-script,${CMAKE_CURRENT_SOURCE_DIR}/libbpf_mojo.map"
  "LINKER:--wrap=bpf_prog_load")
target_include_directories(lmb PRIVATE
  include ${LIBBPF_ROOT}/include)
target_link_libraries(lmb PRIVATE libbpf_static elf z)
add_dependencies(lmb libbpf_external)

# Static archive of the same sources for the native test binaries
# and the Mojo test-support library. Position-independent so it can
# link into a shared object (also fixing the TLS model for that).
add_library(lmb_static STATIC ${LMB_SOURCES})
set_target_properties(lmb_static PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(lmb_static PRIVATE
  include ${LIBBPF_ROOT}/include)
target_link_libraries(lmb_static PUBLIC libbpf_static elf z)
# Keep the same terminal program-load observer when the bridge archive is
# linked into test executables or the test-support shared library.
target_link_options(lmb_static INTERFACE
  "LINKER:--wrap=bpf_prog_load" "LINKER:--undefined=__wrap_bpf_prog_load")
add_dependencies(lmb_static libbpf_external)

# Owned C eBPF fixtures.
find_program(CLANG_EXE clang REQUIRED)
add_custom_command(
  OUTPUT ${CMAKE_BINARY_DIR}/fixtures/ring_test.bpf.o
  COMMAND ${CMAKE_COMMAND} -E make_directory
    ${CMAKE_BINARY_DIR}/fixtures
  COMMAND ${CLANG_EXE} --target=bpf -O2 -g -Wall
    -I${LIBBPF_ROOT}/include
    -I/usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu
    -c ${LMB_ROOT}/tests/fixtures/bpf/ring_test.bpf.c
    -o ${CMAKE_BINARY_DIR}/fixtures/ring_test.bpf.o
  DEPENDS ${LMB_ROOT}/tests/fixtures/bpf/ring_test.bpf.c
  VERBATIM)
add_custom_target(bpf_fixtures ALL
  DEPENDS ${CMAKE_BINARY_DIR}/fixtures/ring_test.bpf.o)
add_dependencies(bpf_fixtures libbpf_external)

set(GENERIC_FIXTURE_OUTPUTS)
foreach(variant generic_object generic_nomap generic_tracing)
  set(fixture_flags)
  if(variant STREQUAL "generic_nomap")
    list(APPEND fixture_flags -DGENERIC_NO_MAP)
  elseif(variant STREQUAL "generic_tracing")
    list(APPEND fixture_flags -DGENERIC_TRACING)
  endif()
  add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/fixtures/${variant}.bpf.o
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/fixtures
    COMMAND ${CLANG_EXE} --target=bpf -O2 -g -Wall ${fixture_flags}
      -I${LIBBPF_ROOT}/include
      -I/usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu
      -c ${LMB_ROOT}/tests/fixtures/bpf/generic_object.bpf.c
      -o ${CMAKE_BINARY_DIR}/fixtures/${variant}.bpf.o
    DEPENDS ${LMB_ROOT}/tests/fixtures/bpf/generic_object.bpf.c
    VERBATIM)
  list(APPEND GENERIC_FIXTURE_OUTPUTS ${CMAKE_BINARY_DIR}/fixtures/${variant}.bpf.o)
endforeach()
add_custom_target(generic_fixtures ALL DEPENDS ${GENERIC_FIXTURE_OUTPUTS})
add_dependencies(generic_fixtures libbpf_external)

add_custom_command(
  OUTPUT ${CMAKE_BINARY_DIR}/fixtures/generic_maps.bpf.o
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/fixtures
  COMMAND ${CLANG_EXE} --target=bpf -O2 -g -Wall
    -I${LIBBPF_ROOT}/include
    -I/usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu
    -c ${LMB_ROOT}/tests/fixtures/bpf/generic_maps.bpf.c
    -o ${CMAKE_BINARY_DIR}/fixtures/generic_maps.bpf.o
  DEPENDS ${LMB_ROOT}/tests/fixtures/bpf/generic_maps.bpf.c
  VERBATIM)
add_custom_target(generic_maps_fixture ALL
  DEPENDS ${CMAKE_BINARY_DIR}/fixtures/generic_maps.bpf.o)
add_dependencies(generic_maps_fixture libbpf_external)

# Tracepoint example: probe object, trigger, and C reference
# consumer. Driven by tests/live/*.py, not by CTest.
add_custom_command(
  OUTPUT ${CMAKE_BINARY_DIR}/examples/probe.bpf.o
  COMMAND ${CMAKE_COMMAND} -E make_directory
    ${CMAKE_BINARY_DIR}/examples
  COMMAND ${CLANG_EXE} --target=bpf -O2 -g -Wall
    -I${LIBBPF_ROOT}/include
    -I/usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu
    -I${LMB_ROOT}/examples/tracepoint
    -c ${LMB_ROOT}/examples/tracepoint/probe.bpf.c
    -o ${CMAKE_BINARY_DIR}/examples/probe.bpf.o
  DEPENDS ${LMB_ROOT}/examples/tracepoint/probe.bpf.c
    ${LMB_ROOT}/examples/tracepoint/event.h
  VERBATIM)
add_custom_target(example_probe ALL
  DEPENDS ${CMAKE_BINARY_DIR}/examples/probe.bpf.o)
add_dependencies(example_probe libbpf_external)

add_executable(tracepoint_trigger
  ${LMB_ROOT}/examples/tracepoint/trigger.c)
set_target_properties(tracepoint_trigger PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/examples)

add_executable(reference_consumer
  ${LMB_ROOT}/tests/native/reference_consumer.c)
target_include_directories(reference_consumer PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${LMB_ROOT}/examples/tracepoint
  ${LIBBPF_ROOT}/include)
target_link_libraries(reference_consumer PRIVATE lmb_static)
add_dependencies(reference_consumer libbpf_external)
set_target_properties(reference_consumer PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/examples)

enable_testing()
function(lmb_test name)
  add_executable(test_${name} ${LMB_ROOT}/tests/native/${name}.c)
  target_include_directories(test_${name} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LMB_ROOT}/tests/native
    ${LIBBPF_ROOT}/include)
  target_link_libraries(test_${name} PRIVATE lmb_static)
  add_dependencies(test_${name} libbpf_external)
  add_test(NAME ${name}
    COMMAND test_${name} ${CMAKE_BINARY_DIR}/fixtures/ring_test.bpf.o)
  set_tests_properties(${name} PROPERTIES
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    SKIP_RETURN_CODE 77)
endfunction()

lmb_test(ring_framing)

# Exercise the host selector with a link-time syscall guard. A regression
# must fail before BPF execution, including the privilege probe.
add_executable(test_ring_framing_host_guard
  ${LMB_ROOT}/tests/native/ring_framing.c)
target_compile_definitions(test_ring_framing_host_guard PRIVATE LMB_HOST_GUARD_TEST)
target_include_directories(test_ring_framing_host_guard PRIVATE
  include ${LMB_ROOT}/tests/native ${LIBBPF_ROOT}/include)
target_link_libraries(test_ring_framing_host_guard PRIVATE lmb_static)
target_link_options(test_ring_framing_host_guard PRIVATE "LINKER:--wrap=syscall")
add_test(NAME ring_framing_host_guard COMMAND test_ring_framing_host_guard
  ${CMAKE_BINARY_DIR}/fixtures/ring_test.bpf.o)
set_tests_properties(ring_framing_host_guard PROPERTIES
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
  ENVIRONMENT "LMB_HOST_ONLY=1;ASAN_OPTIONS=allocator_may_return_null=1")

lmb_test(fake_source)
lmb_test(poll_semantics)
lmb_test(attach_rollback)
lmb_test(map_access)

# Parse and inspect real libbpf objects. The load boundary is intercepted
# with failures and scripted program outcomes; every BPF syscall is
# intercepted before execution and unexpected requests abort the test.
add_executable(test_generic_object ${LMB_ROOT}/tests/native/generic_object.c)
target_include_directories(test_generic_object PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include ${LIBBPF_ROOT}/include)
target_link_libraries(test_generic_object PRIVATE lmb_static)
target_link_options(test_generic_object PRIVATE
  "LINKER:--wrap=bpf_object__load" "LINKER:--wrap=bpf_object__close"
  "LINKER:--wrap=bpf_object__open_mem" "LINKER:--wrap=bpf_program__set_attach_target"
  "LINKER:--wrap=malloc" "LINKER:--wrap=calloc" "LINKER:--wrap=syscall")
add_dependencies(test_generic_object generic_fixtures)
add_test(NAME generic_object COMMAND test_generic_object
  ${CMAKE_BINARY_DIR}/fixtures/generic_object.bpf.o
  ${CMAKE_BINARY_DIR}/fixtures/generic_nomap.bpf.o
  ${CMAKE_BINARY_DIR}/fixtures/generic_tracing.bpf.o)

# Permanent host-only guard for the complete selected suite, including the
# shared library's statically bundled libbpf. Never package this library.
# Keep it uninstrumented even in sanitizer trees: preloading ASan into
# unrelated CTest/shell utilities would pollute the validation harness.
add_library(lmb_host_guard SHARED ${LMB_ROOT}/tests/support/generic_host_guard.c)
target_compile_definitions(lmb_host_guard PRIVATE LMB_GUARD_PRELOAD)
target_link_libraries(lmb_host_guard PRIVATE ${CMAKE_DL_LIBS})
if(LMB_SANITIZE)
  target_compile_options(lmb_host_guard PRIVATE -fno-sanitize=all)
  target_link_options(lmb_host_guard PRIVATE -fno-sanitize=all)
endif()

add_executable(test_generic_maps ${LMB_ROOT}/tests/native/generic_maps.c
  ${LMB_ROOT}/tests/support/generic_host_guard.c)
target_include_directories(test_generic_maps PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include ${LIBBPF_ROOT}/include)
target_link_libraries(test_generic_maps PRIVATE lmb_static)
target_link_options(test_generic_maps PRIVATE
  "LINKER:--wrap=bpf_object__load" "LINKER:--wrap=bpf_object__close"
  "LINKER:--wrap=bpf_object__open_mem" "LINKER:--wrap=bpf_map__fd"
  "LINKER:--wrap=libbpf_num_possible_cpus" "LINKER:--wrap=bpf_map_lookup_elem"
  "LINKER:--wrap=bpf_map_update_elem" "LINKER:--wrap=malloc"
  "LINKER:--wrap=syscall" "LINKER:--wrap=sysconf")
add_dependencies(test_generic_maps generic_maps_fixture)
add_test(NAME generic_maps COMMAND test_generic_maps
  ${CMAKE_BINARY_DIR}/fixtures/generic_maps.bpf.o)
set_tests_properties(generic_maps PROPERTIES
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# Generic ABI contract probe: dlsym-based acceptance battery for
# docs/generic-abi-v1.md. Takes the candidate shared library plus the
# fixture object; Part A always runs. Host-only selection explicitly
# omits Part B before any optional backend, privilege probe, or load.
# In the default scope Part B SKIP-reports until the full generic
# implementation lands.
add_executable(test_generic_abi_probe
  ${LMB_ROOT}/tests/native/generic_abi_probe.c)
target_include_directories(test_generic_abi_probe PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${LMB_ROOT}/tests/native
  ${LIBBPF_ROOT}/include)
target_link_libraries(test_generic_abi_probe PRIVATE ${CMAKE_DL_LIBS})
add_dependencies(test_generic_abi_probe libbpf_external bpf_fixtures
  generic_maps_fixture)
add_test(NAME generic_abi_probe
  COMMAND test_generic_abi_probe $<TARGET_FILE:lmb>
    ${CMAKE_BINARY_DIR}/fixtures/ring_test.bpf.o
    ${CMAKE_BINARY_DIR}/fixtures/generic_maps.bpf.o)
set_tests_properties(generic_abi_probe PROPERTIES
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# Old-header consumer fixture: exercises all eleven v1 operations
# through the frozen header only, linked against the candidate
# shared library.
add_executable(test_old_consumer_v1
  ${LMB_ROOT}/tests/native/old_consumer_v1.c)
target_include_directories(test_old_consumer_v1 PRIVATE
  ${LMB_ROOT}/tests/native)
target_link_libraries(test_old_consumer_v1 PRIVATE lmb)
add_test(NAME old_consumer_v1 COMMAND test_old_consumer_v1)
set_tests_properties(old_consumer_v1 PROPERTIES
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# ring_framing intentionally passes a giant allocation size; ASan must
# return NULL instead of aborting. Non-sanitizer binaries ignore it.
set_tests_properties(ring_framing PROPERTIES
  ENVIRONMENT "ASAN_OPTIONS=allocator_may_return_null=1")

# The shared library must export exactly the public operations.
add_test(NAME exports
  COMMAND sh ${LMB_ROOT}/tests/native/check_exports.sh
    $<TARGET_FILE:lmb>)
set_tests_properties(exports PROPERTIES
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# Test-support library for the Mojo boundary tests: synthetic input
# through the real framing code. Test-only; never installed or
# packaged. Only the lmb_test_* helpers are visible.
add_library(lmb_testfake SHARED ${LMB_ROOT}/tests/support/fake_session.c)
set_target_properties(lmb_testfake PROPERTIES
  OUTPUT_NAME lmb_testfake
  LINK_DEPENDS ${LMB_ROOT}/tests/support/lmb_testfake.map)
target_link_options(lmb_testfake PRIVATE
  "LINKER:--version-script,${LMB_ROOT}/tests/support/lmb_testfake.map")
target_include_directories(lmb_testfake PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${LIBBPF_ROOT}/include)
target_link_libraries(lmb_testfake PRIVATE lmb_static)
add_dependencies(lmb_testfake libbpf_external)
add_test(NAME testfake_exports
  COMMAND sh ${LMB_ROOT}/tests/support/check_testfake_exports.sh
    $<TARGET_FILE:lmb_testfake>)
set_tests_properties(testfake_exports PROPERTIES
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# The guard belongs in native leaves, not the CTest process or its shell
# orchestration. Host twins keep test accounting explicit; the suite runner
# selects each host check once and omits these twins in the default scope.
function(lmb_guarded_host_test name target)
  add_test(NAME native_host_${name}
    COMMAND ${CMAKE_COMMAND} -E env LMB_HOST_ONLY=1
      "LD_PRELOAD=$<TARGET_FILE:lmb_host_guard>"
      $<TARGET_FILE:${target}> ${ARGN})
  set_tests_properties(native_host_${name} PROPERTIES
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endfunction()
lmb_guarded_host_test(ring_framing test_ring_framing_host_guard
  ${CMAKE_BINARY_DIR}/fixtures/ring_test.bpf.o)
set_tests_properties(native_host_ring_framing PROPERTIES
  ENVIRONMENT "ASAN_OPTIONS=allocator_may_return_null=1")
lmb_guarded_host_test(fake_source test_fake_source
  ${CMAKE_BINARY_DIR}/fixtures/ring_test.bpf.o)
lmb_guarded_host_test(generic_object test_generic_object
  ${CMAKE_BINARY_DIR}/fixtures/generic_object.bpf.o
  ${CMAKE_BINARY_DIR}/fixtures/generic_nomap.bpf.o
  ${CMAKE_BINARY_DIR}/fixtures/generic_tracing.bpf.o)
lmb_guarded_host_test(generic_maps test_generic_maps
  ${CMAKE_BINARY_DIR}/fixtures/generic_maps.bpf.o)
lmb_guarded_host_test(generic_abi_probe test_generic_abi_probe
  $<TARGET_FILE:lmb> ${CMAKE_BINARY_DIR}/fixtures/ring_test.bpf.o
  ${CMAKE_BINARY_DIR}/fixtures/generic_maps.bpf.o)
lmb_guarded_host_test(old_consumer_v1 test_old_consumer_v1)

# Partial ABI stub for the incompatible-library test: every
# operation except lmb_close. Test-only; never installed.
add_library(lmb_stub SHARED ${LMB_ROOT}/tests/support/stub_partial.c)
set_target_properties(lmb_stub PROPERTIES OUTPUT_NAME lmb_stub)
