add_library(ldapp 
    ldapp.cpp
    result.cpp
)
add_library(ldapp::ldapp ALIAS ldapp)

target_compile_features(ldapp PUBLIC cxx_std_23)