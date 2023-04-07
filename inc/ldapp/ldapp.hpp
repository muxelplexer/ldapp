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
#include "ldapp/sasl_connection.hpp"

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



    using control_ptr = std::unique_ptr<LDAPControl, control_deleter>;
    using control_vector = std::vector<control_ptr>;
    using ldap_ptr = std::unique_ptr<LDAP, ldap_deleter>;

    class instance
    {
    public:
        instance(const std::string_view ldap_path, const std::string_view binddn, const std::string_view password);
        instance(const instance& inst) = delete;
        const instance& operator=(const instance& inst) = delete;
        operator LDAP*() { return this->m_Ptr.get(); }

        void connect();
        void sasl_bind(const std::string_view binddn, const std::string_view pasword);

        void search(const std::string& searchdn, const std::string_view search_filter);






    private:
        static LDAP* initialize(const std::string_view ldap_path);
        void print_entry(LDAPMessage* entry);
        control_ptr m_SCtrl = nullptr;
        control_ptr m_CCtrl = nullptr;
        ldap_ptr m_Ptr = nullptr;
        std::unique_ptr<sasl_connection> m_Con = nullptr;
        bool m_Connected = false;
        bool m_Bound = false;
    };
}