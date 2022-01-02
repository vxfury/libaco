CMAKE_MINIMUM_REQUIRED(VERSION 3.5 FATAL_ERROR)
PROJECT(libaco VERSION 1.2.2 LANGUAGES C CXX ASM)

LIST(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_SOURCE_DIR}/cmake)

INCLUDE(GNUInstallDirs)
INCLUDE(CMakePackageConfigHelpers)

INCLUDE_DIRECTORIES(src)

##
# Options
##
OPTION(ACO_CHECK "Enable libaco testing" ON)
OPTION(ACO_BENCH "Enable libaco testing" ON)
OPTION(ACO_SHARE_FPENV "Enable share FPU MXCSR env" OFF)
OPTION(ACO_VALGRIND "Enable the use of valgrind" OFF)
OPTION(ACO_M32 "Enable m32 compilation" OFF)
OPTION(ACO_ASAN "Enable address sanitizer" OFF)
OPTION(ACO_COVERAGE "Enable code coverage" OFF)

##
# Project directories definition
##
SET(__INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
SET(__SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
SET(__TEST_DIR ${CMAKE_CURRENT_LIST_DIR}/tests)
SET(__BENCH_DIR ${CMAKE_CURRENT_LIST_DIR}/bench)
SET(__INC_INSDIR ${CMAKE_INSTALL_INCLUDEDIR})
SET(__LIB_INSDIR ${CMAKE_INSTALL_LIBDIR})
SET(__CONF_INSDIR ${__LIB_INSDIR}/cmake/${PROJECT_NAME})

##
# Target
##
SET(__TARGET_NAME aco)
SET(__TARGET lib${__TARGET_NAME})

FILE(GLOB_RECURSE __HDRS ${__HDRS} ${__INC_DIR}/*.h)

ADD_LIBRARY(${__TARGET} ${__HDRS} ${__SRC_DIR}/aco.c ${__SRC_DIR}/acosw.S)
ADD_LIBRARY(${PROJECT_NAME}::${__TARGET_NAME} ALIAS ${__TARGET})
SET_TARGET_PROPERTIES(
  ${__TARGET} PROPERTIES C_STANDARD 90 OUTPUT_NAME "${__TARGET_NAME}"
)

TARGET_INCLUDE_DIRECTORIES(
  ${__TARGET} PRIVATE ${__SRC_DIR}
  PUBLIC $<INSTALL_INTERFACE:${__INC_INSDIR}> $<BUILD_INTERFACE:${__INC_DIR}>
         $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
)

INSTALL(FILES ${__HDRS} DESTINATION ${__INC_INSDIR})

FUNCTION (aco_target_configure target)
  IF (MSVC)
    TARGET_COMPILE_DEFINITIONS(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    TARGET_COMPILE_OPTIONS(${target} PRIVATE /Oy /W3)
  ELSE ()
    TARGET_COMPILE_DEFINITIONS(
      ${target}
      PRIVATE $<$<BOOL:${ACO_SHARE_FPENV}>:ACO_CONFIG_SHARE_FPU_MXCSR_ENV>
              $<$<BOOL:${ACO_VALGRIND}>:ACO_USE_VALGRIND>
    )
    TARGET_COMPILE_OPTIONS(
      ${target}
      PRIVATE -Wall
              -Werror
              -Wextra
              -fomit-frame-pointer
              -Wno-missing-field-initializers
              -Wno-type-limits #TODO: fix the code
              $<$<CONFIG:Debug>:-g3
              -O0>
              $<$<BOOL:${ACO_M32}>:-m32>
              $<$<BOOL:${ACO_COVERAGE}>:--coverage>
              $<$<BOOL:${ACO_ASAN}>:-fsanitize=address>
    )
    TARGET_LINK_LIBRARIES(
      ${target}
      PRIVATE ${ARGN} $<$<BOOL:${ACO_M32}>:-m32>
              $<$<BOOL:${ACO_COVERAGE}>:--coverage>
              $<$<BOOL:${ACO_ASAN}>:-fsanitize=address>
              $<$<BOOL:${ACO_ASAN}>:-fno-omit-frame-pointer>
    )
  ENDIF ()
ENDFUNCTION ()

ACO_TARGET_CONFIGURE(${__TARGET})

##
# Testing
##
IF (ACO_CHECK AND EXISTS ${__TEST_DIR})
  IF (NOT TARGET check)
    ENABLE_TESTING()
    ADD_CUSTOM_TARGET(check COMMAND ${CMAKE_CTEST_COMMAND} --timeout 2)
  ENDIF ()
  ADD_SUBDIRECTORY(${__TEST_DIR})
ENDIF ()

##
# Installation
##
INSTALL(TARGETS ${__TARGET} EXPORT ${PROJECT_NAME}Targets
        LIBRARY DESTINATION ${__LIB_INSDIR} ARCHIVE DESTINATION ${__LIB_INSDIR}
)
INSTALL(EXPORT ${PROJECT_NAME}Targets FILE ${PROJECT_NAME}Targets.cmake
        NAMESPACE ${PROJECT_NAME}:: DESTINATION ${__CONF_INSDIR}
)
WRITE_BASIC_PACKAGE_VERSION_FILE(
  ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
  VERSION ${PROJECT_VERSION} COMPATIBILITY AnyNewerVersion
)
CONFIGURE_PACKAGE_CONFIG_FILE(
  ${CMAKE_CURRENT_LIST_DIR}/cmake/Config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
  INSTALL_DESTINATION ${__CONF_INSDIR}
)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
        DESTINATION ${__CONF_INSDIR}
)
EXPORT(EXPORT ${PROJECT_NAME}Targets
       FILE ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Targets.cmake
       NAMESPACE ${PROJECT_NAME}::
)
EXPORT(PACKAGE ${PROJECT_NAME})
