cmake_minimum_required(VERSION 3.22)

set(PATCH_VERSION "1" CACHE INTERNAL "Patch version")
set(PROJECT_VESRION 0.0.${PATCH_VERSION})
project(SHELL_MAKER VERSION ${PROJECT_VESRION})

include_directories(shell_builder)

add_executable(
  shell_builder
  shell_builder/shell_builder.cpp
  shell_builder/main.cpp
)

set_target_properties(
  shell_builder
  PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
)

if (MSVC)
  target_compile_options(shell_builder PRIVATE /W4)
else ()
  target_link_options(shell_builder PRIVATE -static-libgcc -static-libstdc++)

  target_compile_options(
    shell_builder 
    PRIVATE
    -Wall 
    -Wextra 
    -pedantic 
  )
endif()

install(
    TARGETS 
    shell_builder
    RUNTIME DESTINATION . COMPONENT release
)

set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_ALL release)

# CPack area
if (WIN32)
  set(CPACK_GENERATOR "ZIP")
else()
  set(CPACK_GENERATOR "DEB")
endif()
set(CPACK_PACKAGE_VERSION "0.0.1")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "1")
set(CPACK_PACKAGE_CONTACT https://github.com/4l3x777/shell_maker)
include(CPack)