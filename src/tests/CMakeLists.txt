add_executable(tests
    common/bit_field.cpp
    common/cityhash.cpp
    common/fibers.cpp
    common/host_memory.cpp
    common/param_package.cpp
    common/ring_buffer.cpp
    common/unique_function.cpp
    core/core_timing.cpp
    core/network/network.cpp
    tests.cpp
    video_core/buffer_base.cpp
    input_common/calibration_configuration_job.cpp
)

create_target_directory_groups(tests)

target_link_libraries(tests PRIVATE common core input_common)
target_link_libraries(tests PRIVATE ${PLATFORM_LIBRARIES} Catch2::Catch2 Threads::Threads)

add_test(NAME tests COMMAND tests)
