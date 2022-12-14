# This file is part of PSOneScrot
# Copyright 2020 浅倉麗子

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

cmake_minimum_required(VERSION 3.0)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{DOLCESDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{DOLCESDK}/share/dolce.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define DOLCESDK to point to your SDK path!")
  endif()
endif()

project(psonescrot LANGUAGES C)
include("$ENV{DOLCESDK}/share/dolce.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -nostdlib -Wall -Wextra -O3 -std=gnu99")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostdlib")

if(LOG_PRINTF)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLOG_PRINTF")
endif()

add_subdirectory(user_module)

set(ELF "${PROJECT_NAME}.elf")
set(SELF "${PROJECT_NAME}.skprx")

add_executable("${ELF}"
  main.c
)

target_link_libraries("${ELF}"
  SceDebugForDriver_stub
  SceIofilemgrForDriver_stub
  SceModulemgrForDriver_stub
  SceSysclibForDriver_stub
  SceSysmemForDriver_stub
  SceSysrootForKernel_stub
  SceThreadmgrForDriver_stub
  taihenForKernel_stub
  taihenModuleUtils_stub
  scrot_compat
)

dolce_create_self("${SELF}"
  "${ELF}"
  CONFIG exports.yml
  UNSAFE
)
