#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <string_view>
#include <string>
#include <vector>
#include <utility>

#include <ldap.h>
#include "ldapp/exception.hpp"
#include "ldapp/result.hpp"

namespace ldapp
{

    struct ldap_deleter
    {
        void operator()(ldap* ptr) { ldap_unbind_ext_s(ptr, nullptr, nullptr); };
    };
    struct control_deleter
    {
        void operator()(LDAPControl* ptr) { ldap_control_free(ptr); };
    };

    inline result handle_ldap_function(auto function, auto... args)
    {
        result rc = static_cast<result>(function(
            std::forward<decltype(args)>(args)...
        ));

        if (results::is_error(rc)) throw ldapp::exception(rc);
        return rc;
    }


    using control_ptr = std::unique_ptr<LDAPControl, control_deleter>;
    using control_vector = std::vector<control_ptr>;
    using ldap_ptr = std::unique_ptr<LDAP, ldap_deleter>;

    class instance
    {
    public:
        instance(const std::string_view ldap_path);
        instance(const instance& inst) = delete;
        const instance& operator=(const instance& inst) = delete;
        operator LDAP*() { return this->m_Ptr.get(); }

        void connect();
        void sasl_bind();
        void sasl_unbind();






    private:
        static ldap_ptr initialize(const std::string_view ldap_path);
        void print_entry(LDAPMessage* entry);
        control_ptr m_SCtrl = nullptr;
        control_ptr m_CCtrl = nullptr;
        ldap_ptr m_Ptr = nullptr;
    };
}