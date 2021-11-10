#pragma once
#ifndef FUNCWORKER_HPP__
#define FUNCWORKER_HPP__

#include "basic.hpp"

namespace manager
{

class worker
{
public:
    net::ip::address address_;
    short unsigned port_;

    worker(char const * addr, int port):
        address_{net::ip::make_address(addr)},
        port_{static_cast<short unsigned>(port)} {}
};

auto operator<< (std::ostream& os, worker const& w) -> std::ostream&
{
    os << w.address_.to_string() << ":" << w.port_;
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
        assert (s.address_.is_v4());
        return s.address_.to_v4().to_ulong() * 1000 + s.port_;
    }
};

bool operator==(worker const &a, worker const &b)
{
    return a.address_ == b.address_ and a.port_ == b.port_;
}

} // namespace manager

#endif // FUNCWORKER_HPP__
