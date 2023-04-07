#pragma once
#include <ldap.h>
#include <array>
#include <string_view>
#include <utility>

namespace ldapp
{
    namespace {
        using namespace std::literals;
        constinit static std::array messages
        {
            "Success"sv,
            "Operations Error"sv,
            "Protocol Error"sv,
            "Timelimit Exceeded"sv,
            "Sizelimit Exceeded"sv,
            "Compare False"sv,
            "Comapre True"sv,
            "Authentication Method not supported"sv,
            "Stronger Authentication Method required"sv,
            "Unused"sv,                                    // LDAPv2 Error
            "Referral"sv,
            "Adminlimit Exceeded"sv,
            "Unavailable Critical Extension"sv,
            "Confidentiality Required"sv,
            "SASL Bind In Progess"sv,
            "No Such Attribute"sv
            "Undefined Type"sv,
            "Inappropriate Matching"sv
            "Constraint Violation"sv
            "Type or Value Exists"sv
            "Invalid Syntax"sv,
            "No Such Object"sv,
            "Alias Problem"sv,
            "Invalid DN Syntax"sv,
            "Unused"sv,                                    // LDAPv2 Error
            "Alias Deref Problem"sv
        };
        constinit static int messages_size = messages.size();

        constinit static std::array api_messages
        {
            "Server Down"sv,
            "Local Error"sv,
            "Encoding Error"sv,
            "Decoding Error"sv,
            "Timeout"sv,
            "Auth Unknown"sv,
            "Filter Error"sv,
            "User Cancelled"sv,
            "Param Error"sv,
            "No Memory"sv,
            "Connect Error"sv,
            "Not Supported"sv,
            "Control not fount"sv,
            "No results returned"sv,
            "More results to return"sv,
            "Client Loop"sv,
            "Referral Limit Exceeded"sv,
            "X Connecting"sv
        };
        constinit static int api_messages_size = api_messages.size();
    };

    enum class result
    {
        SUCCESS                         = LDAP_SUCCESS,
        OPERATIONS_ERROR                = LDAP_OPERATIONS_ERROR,

        TIMELIMIT_EXCEEDED              = LDAP_TIMELIMIT_EXCEEDED,
        SIZELIMIT_EXCEEDED              = LDAP_SIZELIMIT_EXCEEDED,

        COMPARE_FALSE                   = LDAP_COMPARE_FALSE,
        COMPARE_TRUE                    = LDAP_COMPARE_TRUE,

        AUTH_METHOD_NOT_SUPPORTED       = LDAP_AUTH_METHOD_NOT_SUPPORTED,
        STRONG_AUTH_NOT_SUPPORTED       = AUTH_METHOD_NOT_SUPPORTED,
        STRONG_AUTH_REQUIRED            = LDAP_STRONG_AUTH_REQUIRED,
        STRONGER_AUTH_REQUIRED          = STRONG_AUTH_REQUIRED,

        REFERRAL                        = LDAP_REFERRAL,
        ADMINLIMIT_EXCEEDED             = LDAP_ADMINLIMIT_EXCEEDED,
        UNAVAILABLE_CRITICAL_EXTENSION  = LDAP_UNAVAILABLE_CRITICAL_EXTENSION,
        CONFIDENTIALITY_REQUIRED        = LDAP_CONFIDENTIALITY_REQUIRED,
        SASL_BIND_IN_PROGRESS           = LDAP_SASL_BIND_IN_PROGRESS,

        NO_SUCH_ATTRIBUTE               = LDAP_NO_SUCH_ATTRIBUTE,
        UNDEFINED_TYPE                  = LDAP_UNDEFINED_TYPE,
        INAPPROPRIATE_MATCHING          = LDAP_INAPPROPRIATE_MATCHING,
        CONSTRAINT_VIOLATION            = LDAP_CONSTRAINT_VIOLATION,
        TYPE_OR_VALUE_EXISTS            = LDAP_TYPE_OR_VALUE_EXISTS,
        INVALID_SYNTAX                  = LDAP_INVALID_SYNTAX,

        NO_SUCH_OBJECT                  = LDAP_NO_SUCH_OBJECT,
        ALIAS_PROBLEM                   = LDAP_ALIAS_PROBLEM,
        INVALID_DN_SYNTAX               = LDAP_INVALID_DN_SYNTAX,
        ALIAS_DEREF_PROBLEM             = LDAP_ALIAS_DEREF_PROBLEM,
    };

    namespace results
    {
        [[nodiscard]] constexpr bool is_error(const result r) { return std::to_underlying(r) != 0; };
        [[nodiscard]] constexpr bool is_api_error(const result r) { return std::to_underlying(r) < 0; };
        [[nodiscard]] constexpr bool is_api_result(const result r) { return std::to_underlying(r) <= 0; };
        [[nodiscard]] constexpr bool result_in_range(const result r, const int lb, const int hb)
        { 
            return (lb <= std::to_underlying(r)) && (hb <= std::to_underlying(r));
        }
        [[nodiscard]] constexpr bool is_attr_error(const result r)
        {
            return result_in_range(r, 0x10, 0x15);
        }
        [[nodiscard]] constexpr bool is_name_error(const result r)
        {
            return result_in_range(r, 0x20, 0x24);
        }
        [[nodiscard]] constexpr std::string_view get_message(const result r)
        {
            if (r == result::SUCCESS) return messages[0];

            std::string_view* msg_iterator = nullptr;
            int size = 0;
            int res_code = std::to_underlying(r);

            if (is_api_error(r))
            {
                res_code *= -1;
                res_code -= 1;
                msg_iterator = std::begin(api_messages);
                size = api_messages.size();
            } else
            {
                msg_iterator = std::begin(messages);
                size = messages.size();
            }

            if (res_code >= size) return "Unknown Error";
            else return *(msg_iterator + res_code);
        }
    }


}