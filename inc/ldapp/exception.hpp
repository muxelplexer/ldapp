#pragma once
#include <exception>
#include "result.hpp"

namespace ldapp
{
    class exception : std::exception
    {
    public:
        exception(const result r) : error{results::get_message(r)} {};

        inline const char* what() const noexcept override { return error.data(); };

    private:
        std::string_view error;
    };

    inline result handle_ldap_function(auto function, auto... args)
    {
        result rc = static_cast<result>(function(
            std::forward<decltype(args)>(args)...
        ));

        if (results::is_error(rc)) throw ldapp::exception(rc);
        return rc;
    }
}