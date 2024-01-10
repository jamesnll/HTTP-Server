#!/usr/bin/env bash

# Exit the script if any command fails
set -e

# Output file for CMakeLists.txt
input_file="files.txt"
output_file="CMakeLists.txt"

# Function to generate CMakeLists-like content
generate_cmake_content() {
  local entity="$1"
  shift
  local sources=""
  local headers=""
  local libraries=""

  for file in "$@"; do
    if [[ $file == *".c" ]]; then
      sources="${sources}    \${CMAKE_SOURCE_DIR}/$file\n"
      echo "list(APPEND SOURCES \${CMAKE_SOURCE_DIR}/$file)" >> "$output_file"
    elif [[ $file == *".h" ]]; then
      headers="${headers}    \${CMAKE_SOURCE_DIR}/$file\n"
      echo "list(APPEND HEADERS \${CMAKE_SOURCE_DIR}/$file)" >> "$output_file"
    else
      libraries="${libraries} $file"
    fi
  done

  echo "" >> "$output_file"
  echo "set(${entity}_SOURCES" >> "$output_file"
  echo -e "$sources)" >> "$output_file"
  echo "" >> "$output_file"
  echo "set(${entity}_HEADERS" >> "$output_file"
  echo -e "$headers)" >> "$output_file"
  echo "" >> "$output_file"
  echo "add_executable($entity \${${entity}_SOURCES})" >> "$output_file"
  echo "" >> "$output_file"

  # Add target_link_libraries for the entity
  for library in $libraries; do
    echo "target_link_libraries($entity PRIVATE $library)" >> "$output_file"
  done
  echo "" >> "$output_file"
}

# Additional code
{
  # Read the first line of files.txt to determine the first target
  first_target=$(awk '{print $1; exit}' "$input_file")
  echo "cmake_minimum_required(VERSION 3.12)" > "$output_file"
  echo "" >> "$output_file"
  echo "project($first_target" >> "$output_file"
  echo "        VERSION 0.0.1" >> "$output_file"
  echo "        DESCRIPTION \"\"" >> "$output_file"
  echo "        LANGUAGES C)" >> "$output_file"
  echo "" >> "$output_file"
  echo "message(STATUS \"Compiler being used: \${CMAKE_C_COMPILER}\")" >> "$output_file"
  echo "" >> "$output_file"
  echo "set(CMAKE_C_STANDARD 17)" >> "$output_file"
  echo "set(CMAKE_C_STANDARD_REQUIRED ON)" >> "$output_file"
  echo "set(CMAKE_C_EXTENSIONS OFF)" >> "$output_file"
  echo "" >> "$output_file"

  # Read the file and process lines
  targets=()  # Array to store target names
  while IFS= read -r line; do
    arr=($line)
    if [ "${#arr[@]}" -ge 2 ]; then
      entity="${arr[0]}"
      files="${arr[@]:1}"
      targets+=("$entity")  # Add the target name to the array
      generate_cmake_content "$entity" $files
    fi
  done < "$input_file"

  # Extract the compiler name without the path
  echo "message(\"C Compiler: \${CMAKE_C_COMPILER}\")" >> "$output_file"
  echo "get_filename_component(COMPILER_NAME \"\${CMAKE_C_COMPILER}\" NAME_WE)" >> "$output_file"
  echo "message(\"COMPILER_NAME: \${COMPILER_NAME}\")" >> "$output_file"
  echo "" >> "$output_file"

  echo "function(split_string_into_list _input_string _output_list)" >> "$output_file"
  echo "    string(REGEX REPLACE \"[ ]+\" \";\" _split_list \"\${_input_string}\")" >> "$output_file"
  echo "    set(\${_output_list} \${_split_list} PARENT_SCOPE)" >> "$output_file"
  echo "endfunction()" >> "$output_file"
  echo "" >> "$output_file"

  # Import warning_flags.txt
  echo "file(STRINGS \"\${CMAKE_SOURCE_DIR}/flags/\${COMPILER_NAME}/warning_flags.txt\" WARNING_FLAGS_STRING)" >> "$output_file"
  echo "split_string_into_list(\"\${WARNING_FLAGS_STRING}\" WARNING_FLAGS_LIST)" >> "$output_file"
  echo "" >> "$output_file"

  # Import analyzer_flags.txt
  echo "file(STRINGS \"\${CMAKE_SOURCE_DIR}/flags/\${COMPILER_NAME}/analyzer_flags.txt\" ANALYZER_FLAGS_STRING)" >> "$output_file"
  echo "split_string_into_list(\"\${ANALYZER_FLAGS_STRING}\" ANALYZER_FLAGS_LIST)" >> "$output_file"
  echo "" >> "$output_file"

  # Import debug_flags.txt
  echo "file(STRINGS \"\${CMAKE_SOURCE_DIR}/flags/\${COMPILER_NAME}/debug_flags.txt\" DEBUG_FLAGS_STRING)" >> "$output_file"
  echo "split_string_into_list(\"\${DEBUG_FLAGS_STRING}\" DEBUG_FLAGS_LIST)" >> "$output_file"
  echo "" >> "$output_file"

  # Import sanitizer_flags.txt
  echo "file(STRINGS \"\${CMAKE_SOURCE_DIR}/flags/\${COMPILER_NAME}/sanitizer_flags.txt\" SANITIZER_FLAGS_STRING)" >> "$output_file"
  echo "split_string_into_list(\"\${SANITIZER_FLAGS_STRING}\" SANITIZER_FLAGS_LIST)" >> "$output_file"
  echo "" >> "$output_file"

  # Common compiler flags
  echo "set(STANDARD_FLAGS" >> "$output_file"
  echo "    -D_POSIX_C_SOURCE=200809L" >> "$output_file"
  echo "    -D_XOPEN_SOURCE=700" >> "$output_file"
  echo "    -D_GNU_SOURCE" >> "$output_file"
  echo "    -D_DARWIN_C_SOURCE" >> "$output_file"
  echo "    -D__BSD_VISIBLE" >> "$output_file"
  echo "    -Werror" >> "$output_file"
  echo ")" >> "$output_file"
  echo "" >> "$output_file"

  # Loop through targets and set compile options and libraries
  for target in "${targets[@]}"; do
    # Set compiler flags for the target
    echo "# Set compiler flags for the target $target" >> "$output_file"
    echo "target_compile_options($target PRIVATE" >> "$output_file"
    echo "    \${STANDARD_FLAGS}" >> "$output_file"
    echo "    \${WARNING_FLAGS_LIST}" >> "$output_file"
    echo "    \${ANALYZER_FLAGS_LIST}" >> "$output_file"
    echo "    \${DEBUG_FLAGS_LIST}" >> "$output_file"
    echo "    \${SANITIZER_FLAGS_LIST}" >> "$output_file"
    echo ")" >> "$output_file"

    echo "# Add target_link_libraries for $target" >> "$output_file"
    echo "target_link_libraries($target PRIVATE \${SANITIZER_FLAGS_STRING})" >> "$output_file"
    echo "" >> "$output_file"
  done

  echo "if (NOT DEFINED CLANG_FORMAT_NAME)" >> "$output_file"
  echo "    set(CLANG_FORMAT_NAME \"clang-format\")" >> "$output_file"
  echo "endif()" >> "$output_file"
  echo "" >> "$output_file"
  echo "if (NOT DEFINED CLANG_TIDY_NAME)" >> "$output_file"
  echo "    set(CLANG_TIDY_NAME \"clang-tidy\")" >> "$output_file"
  echo "endif()" >> "$output_file"
  echo "" >> "$output_file"
  echo "if (NOT DEFINED CPPCHECK_NAME)" >> "$output_file"
  echo "    set(CPPCHECK_NAME \"cppcheck\")" >> "$output_file"
  echo "endif()" >> "$output_file"
  echo "" >> "$output_file"
  echo "find_program(CLANG_FORMAT NAMES \${CLANG_FORMAT_NAME} REQUIRED)" >> "$output_file"
  echo "find_program(CLANG_TIDY NAMES \${CLANG_TIDY_NAME} REQUIRED)" >> "$output_file"
  echo "find_program(CPPCHECK NAMES \${CPPCHECK_NAME} REQUIRED)" >> "$output_file"
  echo "" >> "$output_file"

  # Format source files using clang-format
  echo "add_custom_target(format" >> "$output_file"
  echo "    COMMAND \${CLANG_FORMAT} --style=file -i \${SOURCES} \${HEADERS}" >> "$output_file"
  echo "    WORKING_DIRECTORY \${CMAKE_SOURCE_DIR}" >> "$output_file"
  echo "    COMMENT \"Running clang-format\"" >> "$output_file"
  echo ")" >> "$output_file"
  echo "" >> "$output_file"

  # Add dependencies for the first target
  echo "add_dependencies($first_target format)" >> "$output_file"
  echo "" >> "$output_file"

  # Add the cppcheck custom command
  echo "add_custom_command(" >> "$output_file"
  echo "    TARGET $first_target POST_BUILD" >> "$output_file"
  echo "    COMMAND \${CLANG_TIDY} \${SOURCES} \${HEADERS} -quiet --warnings-as-errors='*' -checks=*,-llvmlibc-restrict-system-libc-headers,-altera-struct-pack-align,-readability-identifier-length,-altera-unroll-loops,-cppcoreguidelines-init-variables,-cert-err33-c,-modernize-macro-to-enum,-bugprone-easily-swappable-parameters,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,-altera-id-dependent-backward-branch,-concurrency-mt-unsafe,-misc-unused-parameters,-hicpp-signed-bitwise,-google-readability-todo,-cert-msc30-c,-cert-msc50-cpp,-readability-function-cognitive-complexity,-clang-analyzer-security.insecureAPI.strcpy,-cert-env33-c,-android-cloexec-accept,-clang-analyzer-security.insecureAPI.rand,-misc-include-cleaner,-llvm-header-guard -- \${STANDARD_FLAGS} -I/usr/local/include" >> "$output_file"
  echo "    WORKING_DIRECTORY \${CMAKE_SOURCE_DIR}" >> "$output_file"
  echo "    COMMENT \"Running clang-tidy\"" >> "$output_file"
  echo ")" >> "$output_file"
  echo "" >> "$output_file"

  # Check if CMAKE_C_COMPILER starts with "clang" and add custom targets
  echo "if (CMAKE_C_COMPILER MATCHES \".*/clang.*\")" >> "$output_file"
  echo "    # Add a custom target for clang --analyze" >> "$output_file"
  echo "    add_custom_command(" >> "$output_file"
  echo "        TARGET $first_target POST_BUILD" >> "$output_file"
  echo "        COMMAND \${CMAKE_C_COMPILER} --analyzer-output text --analyze -Xclang -analyzer-checker=core --analyze -Xclang -analyzer-checker=deadcode -Xclang -analyzer-checker=security -Xclang -analyzer-disable-checker=security.insecureAPI.DeprecatedOrUnsafeBufferHandling -Xclang -analyzer-checker=unix -Xclang -analyzer-checker=unix \${CMAKE_C_FLAGS} \${STANDARD_FLAGS} \${SOURCES} \${HEADERS}" >> "$output_file"
  echo "        WORKING_DIRECTORY \${CMAKE_SOURCE_DIR}" >> "$output_file"
  echo "        COMMENT \"Running clang --analyze\"" >> "$output_file"
  echo "    )" >> "$output_file"
  echo "" >> "$output_file"
  echo "    # Add a custom command to delete .gch files after the analysis" >> "$output_file"
  echo "    add_custom_command(" >> "$output_file"
  echo "        TARGET $first_target POST_BUILD" >> "$output_file"
  echo "        COMMAND \${CMAKE_COMMAND} -E remove \${CMAKE_SOURCE_DIR}/*.gch" >> "$output_file"
  echo "        COMMENT \"Removing .gch files\"" >> "$output_file"
  echo "    )" >> "$output_file"
  echo "endif ()" >> "$output_file"
  echo "" >> "$output_file"

  # Add a custom target for cppcheck
  echo "add_custom_command(" >> "$output_file"
  echo "    TARGET $first_target POST_BUILD" >> "$output_file"
  echo "    COMMAND \${CPPCHECK} --error-exitcode=1 --force --quiet --inline-suppr --library=posix --enable=all --suppress=missingIncludeSystem --suppress=unusedFunction --suppress=unmatchedSuppression \${SOURCES} \${HEADERS}" >> "$output_file"
  echo "    WORKING_DIRECTORY \${CMAKE_SOURCE_DIR}" >> "$output_file"
  echo "    COMMENT \"Running cppcheck\"" >> "$output_file"
  echo ")" >> "$output_file"
  echo "" >> "$output_file"
}

exit $?
