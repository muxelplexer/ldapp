#pragma once
#include <ldap.h>
#include "utility.hpp"

namespace ldapp
{
    class attribute
    {
    public:
        attribute(const std::string_view name, const std::string_view value);
        attribute(const attribute& attr);
        attribute(attribute&& attr) noexcept;
        ~attribute();

        const attribute& operator=(const attribute& attr)
        {
            return *this = attribute(attr);
        }

        attribute& operator=(attribute&& attr)
        {
            return *this = attribute(attr);
        }

        [[nodiscard]] const std::string_view get_name() const { return this->name; }; 
        [[nodiscard]] const std::string_view get_value() const { return this->value; }; 

    private:
        std::string name;
        std::string value;
    };

    
}