add_executable(headless
    main.cpp
    Platform.cpp
    HeadlessPlatform.h
    HeadlessInput.h
)

target_include_directories(headless PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/..")

find_package(Threads REQUIRED)
target_link_libraries(headless PRIVATE core)
target_link_libraries(headless PRIVATE Threads::Threads ${CMAKE_DL_LIBS})

option(BUILD_HEADLESS_AFL "Build AFL++ headless fuzz harness" OFF)
if (BUILD_HEADLESS_AFL)
    add_executable(headless_afl_arm9_blob
        afl_harness_arm9_blob.cpp
        Platform.cpp
        HeadlessPlatform.h
    )
    target_include_directories(headless_afl_arm9_blob PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/..")
    target_compile_definitions(core PRIVATE MELON_FUZZ_FAST=1)
    target_compile_definitions(headless_afl_arm9_blob PRIVATE MELON_FUZZ_FAST=1)
    target_link_libraries(headless_afl_arm9_blob PRIVATE core)
    target_link_libraries(headless_afl_arm9_blob PRIVATE Threads::Threads ${CMAKE_DL_LIBS})

    add_custom_target(time_harnesses
        COMMAND "${CMAKE_SOURCE_DIR}/tools/aflplusplus/time_harnesses.py"
            --arm9-harness "$<TARGET_FILE:headless_afl_arm9_blob>"
        DEPENDS headless_afl_arm9_blob
        USES_TERMINAL
        VERBATIM
    )
endif()
