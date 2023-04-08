add_library(ldapp 
    attribute.cpp
    entry.cpp
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
target_link_libraries(ldapp PUBLIC ldap lber)