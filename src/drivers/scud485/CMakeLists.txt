# SPDX-License-Identifier: GPL-3.0
# Copyright (C) 2026 changchuanyong
# SCUD 485：daemon 私有帧协议 + 客户端驱动（合并实现，底层共用 SerialPort）
add_library(scud485_bms STATIC
    scud_bms_driver.cpp
)
target_include_directories(scud485_bms
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(scud485_bms PUBLIC ${PUBLIC_DEPENDENCIES} bms_protocol)
