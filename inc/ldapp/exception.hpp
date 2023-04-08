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

}