cmake_minimum_required(VERSION 3.5)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

set(PARTITION_TABLE_CSV_PATH "${CMAKE_CURRENT_LIST_DIR}/partitions.csv")

project(app-template VERSION 1.0.3)