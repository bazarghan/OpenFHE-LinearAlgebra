cmake_minimum_required(VERSION 3.14)
project(
  OpenFHELinearAlgebra
  VERSION 0.1.0
  LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find OpenFHE package
find_package(OpenFHE CONFIG REQUIRED)

if(OpenFHE_FOUND)
  message(STATUS "FOUND PACKAGE OpenFHE")
  message(STATUS "OpenFHE Version: ${BASE_OPENFHE_VERSION}")
  message(STATUS "OpenFHE installed as shared libraries: ${OpenFHE_SHARED}")
  message(STATUS "OpenFHE include files location: ${OpenFHE_INCLUDE}")
  message(STATUS "OpenFHE lib files location: ${OpenFHE_LIBDIR}")
  message(STATUS "OpenFHE Native Backend size: ${OpenFHE_NATIVE_SIZE}")
else()
  message(FATAL_ERROR "PACKAGE OpenFHE NOT FOUND")
endif()

set(CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS})

# Include directories for OpenFHE and other necessary paths
include_directories(${OPENMP_INCLUDES})
include_directories(${OpenFHE_INCLUDE})
include_directories(${OpenFHE_INCLUDE}/third-party/include)
include_directories(${OpenFHE_INCLUDE}/core)
include_directories(${OpenFHE_INCLUDE}/pke)
include_directories(${OpenFHE_INCLUDE}/binfhe)

# Link directories for OpenFHE
link_directories(${OpenFHE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})

# Determine linker flags and libraries based on build type (static or shared)
if(BUILD_STATIC)
  set(CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
  link_libraries(${OpenFHE_STATIC_LIBRARIES})
else()
  set(CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS})
  link_libraries(${OpenFHE_SHARED_LIBRARIES})
endif()

# Create the library target from source files
add_library(OpenFHELinearAlgebra src/EncryptedMatrix.cpp)

# Include directories: both your own headers and OpenFHE's headers
target_include_directories(
  OpenFHELinearAlgebra
  PUBLIC ${PROJECT_SOURCE_DIR}/include
         ${OPENFHE_INCLUDE_DIRS} # OpenFHE's include directories, provided by
                                 # find_package
)

# Link your library against OpenFHE
target_link_libraries(OpenFHELinearAlgebra PUBLIC ${OpenFHE_LIBRARIES})

# --- Testing Setup ---
enable_testing()
include(FetchContent)

FetchContent_Declare(
  googletest URL https://github.com/google/googletest/archive/release-1.12.1.zip
                 DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
# Optional: force shared runtime on Windows
set(gtest_force_shared_crt
    ON
    CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# # Add a test executable add_executable(LinearAlgebraTests
# tests/matrix_tests.cpp) target_link_libraries(LinearAlgebraTests gtest_main
# OpenFHELinearAlgebra)
#
# include(GoogleTest) gtest_discover_tests(LinearAlgebraTests)
