#include "ldapp/attribute.hpp"

namespace ldapp
{
    attribute::attribute(const std::string_view name, const std::string_view value)
        : name{name}, value{value}
    {

    }

    attribute::attribute(const attribute& attr)
        : name{attr.name}, value{attr.value}
    {
        
    }

    attribute::attribute(attribute&& attr) noexcept
        : name{std::move(attr.name)}, value{std::move(attr.value)}
    {
    }

    attribute::~attribute()
    {

    }
}