cmake_minimum_required(VERSION 3.10)
project(antivirus)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Для Windows GUI приложения (не консоль)
set(CMAKE_WIN32_EXECUTABLE ON)

# Добавляем исполняемый файл
add_executable(antivirus WIN32
    antivirus.cpp
)

# Подключаем необходимые библиотеки
target_link_libraries(antivirus
    shell32
    user32
)