cmake_minimum_required(VERSION 3.21)
project(Argon2All LANGUAGES C CXX)

set(CMAKE_VERBOSE_MAKEFILE ON)

# Default to Release when generator doesn't provide a config
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the build type." FORCE)
endif()

# Native Reference project
add_subdirectory(Reference)

# Find dotnet CLI (used to build/test C# projects)
find_program(DOTNET_CLI dotnet)
if(NOT DOTNET_CLI)
  message(FATAL_ERROR "dotnet CLI not found in PATH. Install dotnet SDK to enable dotnet-related targets.")
endif()

message(STATUS "Found dotnet CLI: ${DOTNET_CLI}")

# Path (or solution) to restore/build/test; default is repository root.
set(DOTNET_ROOT_DIR "${CMAKE_SOURCE_DIR}" CACHE PATH "Path to root directory or solution file for dotnet restore/build/test")

# If DOTNET_ROOT_DIR is not a solution file path, we'll generate _dotnet_build.sln in the repo root
if(DOTNET_ROOT_DIR MATCHES "\\.sln$")
  set(DOTNET_SOLUTION "${DOTNET_ROOT_DIR}")
else()
  set(DOTNET_SOLUTION "${CMAKE_SOURCE_DIR}/_dotnet_build.sln")
endif()

# Option: include Windows / UWP projects that require Visual Studio workloads
option(INCLUDE_WINDOWS_PROJECTS "Include UWP/WinUI projects in generated dotnet solution" OFF)

# Gather all .csproj files (relative paths)
file(GLOB_RECURSE CS_PROJS RELATIVE ${CMAKE_SOURCE_DIR} "*.csproj")
message(STATUS "CS_PROJS (raw):")
foreach(cs_proj IN LISTS CS_PROJS)
    message(STATUS "    ${cs_proj}")
endforeach()

# Exclude known Windows/UWP projects by default (unless INCLUDE_WINDOWS_PROJECTS=ON)
set(EXCLUDE_PATTERNS
  "test/TestUwpApp/"
  "test/TestUno/TestUno.UWP/"
)

set(FILTERED_CS_PROJS)
foreach(cs_proj IN LISTS CS_PROJS)
  set(_skip FALSE)
  if(NOT INCLUDE_WINDOWS_PROJECTS)
    foreach(pat IN LISTS EXCLUDE_PATTERNS)
      string(FIND "${cs_proj}" "${pat}" _found)
      if(NOT _found EQUAL -1)
        set(_skip TRUE)
        break()
      endif()
    endforeach()
  endif()
  if(NOT _skip)
    list(APPEND FILTERED_CS_PROJS ${cs_proj})
  endif()
endforeach()

message(STATUS "CS_PROJS (filtered):")
foreach(cs_proj IN LISTS FILTERED_CS_PROJS)
    message(STATUS "    ${cs_proj}")
endforeach()

# Target: generate a lightweight solution file named _dotnet_build.sln in the repo root.
add_custom_target(generate-dotnet-sln
  COMMENT "Generating ${DOTNET_SOLUTION} containing all .csproj files"
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# remove old sln and create a new one; then add projects (POST_BUILD commands on the target)
add_custom_command(TARGET generate-dotnet-sln
  PRE_BUILD
  COMMAND ${CMAKE_COMMAND} -E remove -f ${DOTNET_SOLUTION}
  COMMAND ${DOTNET_CLI} new sln -n _dotnet_build -o ${CMAKE_SOURCE_DIR}
  COMMENT "Creating ${DOTNET_SOLUTION}"
)

if(FILTERED_CS_PROJS)
  # Prepare absolute paths to add to the solution
  set(ABS_CS_PROJS)
  foreach(p IN LISTS FILTERED_CS_PROJS)
    list(APPEND ABS_CS_PROJS "${CMAKE_SOURCE_DIR}/${p}")
  endforeach()

  # Add all projects to the sln (one command per project to avoid overly long command lines)
  foreach(abs IN LISTS ABS_CS_PROJS)
    add_custom_command(TARGET generate-dotnet-sln
      POST_BUILD
      COMMAND ${DOTNET_CLI} sln ${DOTNET_SOLUTION} add "${abs}"
      COMMENT "Adding ${abs} to ${DOTNET_SOLUTION}"
    )
  endforeach()
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(DOTNET_CONFIGURATION "Debug")
else()
    set(DOTNET_CONFIGURATION "Release")
endif()

# Dotnet targets that run with REFERENCE_RUN_PATH pointing at the native binary produced by the 'argon2' target.
# Ensure generate-dotnet-sln runs before dotnet restore/build/test.
add_custom_target(dotnet-restore
  COMMAND ${CMAKE_COMMAND} -E env REFERENCE_RUN_PATH=$<TARGET_FILE:argon2> ${DOTNET_CLI} restore ${DOTNET_SOLUTION}
  DEPENDS argon2 generate-dotnet-sln
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "dotnet restore (REFERENCE_RUN_PATH set to native argon2 binary)"
)

add_custom_target(dotnet-build
  COMMAND ${CMAKE_COMMAND} -E env REFERENCE_RUN_PATH=$<TARGET_FILE:argon2> ${DOTNET_CLI} build ${DOTNET_SOLUTION} --configuration ${DOTNET_CONFIGURATION} 
  DEPENDS dotnet-restore
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "dotnet build (Release) with REFERENCE_RUN_PATH"
)

add_custom_target(dotnet-test
  COMMAND ${CMAKE_COMMAND} -E env REFERENCE_RUN_PATH=$<TARGET_FILE:argon2> ${DOTNET_CLI} test ${DOTNET_SOLUTION} --configuration ${DOTNET_CONFIGURATION}
  DEPENDS dotnet-build
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "dotnet test with REFERENCE_RUN_PATH"
)

add_custom_target(dotnet-build-test-uno-wasm
  COMMAND ${CMAKE_COMMAND} -E env REFERENCE_RUN_PATH=$<TARGET_FILE:argon2> ${DOTNET_CLI} build test/TestUno/TestUno.Wasm  --configuration ${DOTNET_CONFIGURATION}
  DEPENDS dotnet-build
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "dotnet build test uno wasm"
)

add_custom_target(dotnet-build-test-blazor-wasm
  COMMAND ${CMAKE_COMMAND} -E env REFERENCE_RUN_PATH=$<TARGET_FILE:argon2> ${DOTNET_CLI} build test/TestBlazor/Wasm  --configuration ${DOTNET_CONFIGURATION}
  DEPENDS dotnet-build
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "dotnet build test blazor wasm"
)

add_custom_target(dotnet-build-test-blazor-server
  COMMAND ${CMAKE_COMMAND} -E env REFERENCE_RUN_PATH=$<TARGET_FILE:argon2> ${DOTNET_CLI} build test/TestBlazor/Server --configuration ${DOTNET_CONFIGURATION}
  DEPENDS dotnet-build
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "dotnet build test blazor server"
)

add_custom_target(dotnet-build-test-app
  COMMAND ${CMAKE_COMMAND} -E env REFERENCE_RUN_PATH=$<TARGET_FILE:argon2> ${DOTNET_CLI} build test/TestApp --configuration ${DOTNET_CONFIGURATION}
  DEPENDS dotnet-build
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "dotnet build test app"
)

set(TEST_APPS "dotnet-build-test-uno-wasm;dotnet-build-test-blazor-wasm;dotnet-build-test-blazor-server;dotnet-build-test-app")

if(WINDOWS_STORE) # TODO - we should be able to build UWP with proper workloads installed 
    add_custom_target(dotnet-build-test-uwp
        COMMAND ${CMAKE_COMMAND} -E env REFERENCE_RUN_PATH=$<TARGET_FILE:argon2> ${DOTNET_CLI} build test/TestUwpApp --configuration ${DOTNET_CONFIGURATION}
        DEPENDS dotnet-build
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "dotnet build test uwp"
    )

    add_custom_target(dotnet-build-test-uno-uwp
      COMMAND ${CMAKE_COMMAND} -E env REFERENCE_RUN_PATH=$<TARGET_FILE:argon2> ${DOTNET_CLI} build test/TestUno/TestUno.UWP --configuration ${DOTNET_CONFIGURATION}
      DEPENDS dotnet-build
      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
      COMMENT "dotnet build test uno uwp"
    )
    list(APPEND TEST_APPS "dotnet-build-test-uwp" "dotnet-build-test-uno-uwp")
endif()


# Convenience target that builds native and dotnet build
add_custom_target(all-with-dotnet
  ALL
  DEPENDS argon2 dotnet-build
)

# Convenience target that builds the test apps
add_custom_target(dotnet-build-test-apps DEPENDS ${TEST_APPS})

# Find the Windows Kits root directory
set(WINDOWS_KITS_ROOT "")
set(_pf_x86_name "ProgramFiles(x86)")
if(DEFINED ENV{${_pf_x86_name}})
    set(PROGRAM_FILES_X86 "$ENV{${_pf_x86_name}}")
else()
    set(PROGRAM_FILES_X86 "C:/Program Files (x86)")
endif()

# Try to find KitsRoot10 from registry
execute_process(
    COMMAND reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots" /v KitsRoot10
    OUTPUT_VARIABLE REG_OUTPUT
    RESULT_VARIABLE REG_RESULT
    ERROR_QUIET
)

if(REG_RESULT EQUAL 0)
    string(REGEX MATCH "KitsRoot10\\s+REG_SZ\\s+(.*)" MATCHED_LINE "${REG_OUTPUT}")
    if(MATCHED_LINE)
        set(WINDOWS_KITS_ROOT "${CMAKE_MATCH_1}")
    endif()
endif()

# Fallback if registry lookup fails
if(NOT WINDOWS_KITS_ROOT)
    set(WINDOWS_KITS_ROOT "${PROGRAM_FILES_X86}/Windows Kits/10")
endif()

set(SIGNTOOL_EXE "")
set(LATEST_SDK_VERSION "0.0.0.0")

if(EXISTS "${WINDOWS_KITS_ROOT}/bin")
    file(GLOB SDK_VERSIONS "${WINDOWS_KITS_ROOT}/bin/*")
    foreach(SDK_VERSION_DIR IN LISTS SDK_VERSIONS)
        if(IS_DIRECTORY "${SDK_VERSION_DIR}")
            get_filename_component(SDK_VERSION_NAME "${SDK_VERSION_DIR}" NAME)
            # Compare versions to find the newest
            # This is a simplified comparison, a more robust solution might parse version numbers
            if(SDK_VERSION_NAME VERSION_GREATER LATEST_SDK_VERSION)
                set(CURRENT_SIGNTOOL_PATH "${SDK_VERSION_DIR}/x64/signtool.exe")
                if(EXISTS "${CURRENT_SIGNTOOL_PATH}")
                    set(SIGNTOOL_EXE "${CURRENT_SIGNTOOL_PATH}")
                    set(LATEST_SDK_VERSION "${SDK_VERSION_NAME}")
                endif()
            endif()
        endif()
    endforeach()
endif()

if(SIGNTOOL_EXE)
    file(TO_NATIVE_PATH "${SIGNTOOL_EXE}" SIGNTOOL_EXE)
    message(STATUS "Found signtool.exe (x64) at: ${SIGNTOOL_EXE}")
    set(SIGNTOOL_EXE "${SIGNTOOL_EXE}" CACHE FILEPATH "Path to signtool.exe (default: signtool.exe on PATH)")
else()
    message(WARNING "Could not find signtool.exe (x64). Please ensure Windows SDK is installed.")
    set(SIGNTOOL_EXE "signtool.exe" CACHE FILEPATH "Path to signtool.exe (default: signtool.exe on PATH)")
endif()
# Signing options for Windows Authenticode (signtool)
option(SIGN_ASSEMBLIES "Enable signing of produced assemblies/executables on Windows via signtool" ON)
set(SIGNING_CERT_PFX "isopoh-nopass.pfx" CACHE FILEPATH "Path to PFX file to use for signing (optional). If empty, use certificate in store via SIGNING_CERT_SUBJECT.")
set(SIGNING_PFX_PASSWORD "" CACHE STRING "Password for PFX (optional). If empty, signtool will prompt.")
set(SIGNING_CERT_SUBJECT "" CACHE STRING "Certificate subject name to use from store (optional; used when PFX not provided).")
set(SIGNING_TIMESTAMP_URL "http://timestamp.digicert.com" CACHE STRING "Timestamp server URL (use /tr RFC3161 timestamps)")
# Comma or semicolon separated list of project roots relative to repo to sign managed outputs from:
set(
    SIGN_TARGET_PROJECTS
    "lib/Isopoh.Cryptography.SecureArray;lib/Isopoh.Cryptography.Blake2b;lib/Isopoh.Cryptography.Argon2"
    CACHE STRING "Projects to search for managed outputs to sign (relative to source dir)")

if(WIN32 AND SIGN_ASSEMBLIES)
  find_program(POWERSHELL powershell.exe)
  if(NOT POWERSHELL)
    message(FATAL_ERROR "powershell CLI not found in PATH. Install powershell.")
  endif()

  message(STATUS "Windows signing enabled. signtool: ${SIGNTOOL_EXE}")
  message(STATUS "SIGN_FILES script:\n${SIGN_FILES}")
  add_custom_command(TARGET dotnet-build
    POST_BUILD
    COMMENT "Signing selected managed/native outputs using signtool"
    COMMAND ${CMAKE_COMMAND} -E echo "Searching specified projects for bin/Release outputs to sign..."
    # Sign managed outputs under the listed project folders
    COMMAND ${POWERSHELL} -NoProfile -ExecutionPolicy Bypass -Command "SignFiles.ps1 -SignTool ${SIGNTOOL_EXE} -Pfx '${SIGNING_CERT_PFX}' -Pwd '${SIGNING_PFX_PASSWORD}' -Subject '${SIGNING_CERT_SUBJECT}' -TimestampUrl '${SIGNING_TIMESTAMP_URL}' -ProjectRoots '${SIGN_TARGET_PROJECTS}''"
  )
endif()