add_library(ldapp 
    ldapp.cpp
    result.cpp
    sasl_connection.cpp
)
target_include_directories(ldapp
    PUBLIC
        ../inc
)
add_library(ldapp::ldapp ALIAS ldapp)

target_compile_features(ldapp PUBLIC cxx_std_23)