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

set(SCROT_COMPAT "scrot_compat")
set(ELF          "${SCROT_COMPAT}.elf")
set(SELF         "${SCROT_COMPAT}.suprx")
set(SELF_C       "${SCROT_COMPAT}.c")
set(SELF_OBJ     "${SCROT_COMPAT}")

add_executable("${ELF}"
  main.c
)

target_link_libraries("${ELF}"
  SceKernelModulemgr_stub
  SceLibKernel_stub
  taihen_stub
)

dolce_create_self("${SELF}"
  "${ELF}"
  CONFIG exports.yml
  UNSAFE
)

add_custom_target("${SELF_C}.target"
  DEPENDS "${SELF_C}"
)

add_custom_command(
  OUTPUT "${SELF_C}"
  DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/${SELF}"
  COMMAND xxd -i "${SELF}" "${SELF_C}"
  COMMENT "Converting ${SELF} to ${SELF_C}"
)

add_library("${SELF_OBJ}"
  STATIC
  "${SELF_C}"
)
