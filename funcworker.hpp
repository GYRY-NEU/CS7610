#pragma once
#ifndef FUNCWORKER_HPP__
#define FUNCWORKER_HPP__

#include "basic.hpp"

namespace manager
{

struct worker
{
    net::ip::address address;
    short unsigned port;
    bool alive = true;

    worker(char const * addr, int rport):
        address{net::ip::make_address(addr)},
        port{static_cast<short unsigned>(rport)} {}
};

auto operator<< (std::ostream& os, worker const& w) -> std::ostream&
{
    os << w.address.to_string() << ":" << w.port;
    return os;
}

template <typename T>
struct hash
{
    auto operator() (T const& s) const noexcept -> std::size_t { return 0; }
};

template <>
struct hash<worker>
{
    auto operator() (worker const& s) const noexcept -> std::size_t
    {
        assert (s.address.is_v4());
        return s.address.to_v4().to_ulong() * 1000 + s.port;
    }
};

bool operator==(worker const &a, worker const &b)
{
    return a.address == b.address and a.port == b.port;
}

} // namespace manager

#endif // FUNCWORKER_HPP__
