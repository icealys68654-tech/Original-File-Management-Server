cmake_minimum_required(VERSION 3.20)
project(CloudFileServerUmbrella VERSION 1.4.2 LANGUAGES NONE)

find_program(NODE_EXECUTABLE node REQUIRED)
message(STATUS "Node executable: ${NODE_EXECUTABLE}")

add_custom_target(env-guard
  COMMAND "${NODE_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/tools/env-guard.mjs" --file "${CMAKE_SOURCE_DIR}/deploy/systemd/cfs.env.example" --example
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Linting deployment environment template"
  VERBATIM)

add_custom_target(c4-validate
  COMMAND "${NODE_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/tools/c4-validate.mjs"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Validating C4 model and diagram references"
  VERBATIM)

add_custom_target(smoke-probe
  COMMAND "${NODE_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/tools/smoke-probe.mjs" "$ENV{CFS_BASE_URL}"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Probing configured Cloud File Server endpoint"
  VERBATIM)

add_custom_target(ci-validate DEPENDS env-guard c4-validate)
add_custom_target(full-check
  COMMAND "${NODE_EXECUTABLE}" --test "${CMAKE_SOURCE_DIR}/tools/test/tooling.test.mjs"
  COMMAND "${NODE_EXECUTABLE}" --test
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/mvc"
  DEPENDS env-guard c4-validate
  COMMENT "Running umbrella tooling and application regression suites"
  VERBATIM)
