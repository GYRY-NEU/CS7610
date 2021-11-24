#pragma once
#ifndef FUNCSCHEDULER_HPP__
#define FUNCSCHEDULER_HPP__

#include "basic.hpp"

#include <atomic>

namespace manager
{

namespace worker
{

struct worker
{
    net::ip::address address;
    short unsigned port;
    std::size_t const capacity;
    std::atomic<std::size_t> jobs = 0;
    bool alive = true;

    worker(char const * addr, int rport, std::size_t cap):
        address{net::ip::make_address(addr)},
        port{static_cast<short unsigned>(rport)},
        capacity{cap} {}

    inline
    double load()
    {
        return static_cast<double>(jobs) / capacity;
    }
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

} // nsmespace worker

namespace scheduler
{

class scheduler
{
    // all workers
    tbb::concurrent_unordered_set<worker::worker, worker::hash<worker::worker>> workers_;

    // strand name to worker
    tbb::concurrent_unordered_map<basic::strhash, worker::worker*> strand_record_;

    net::io_context & ioc_;
public:
    scheduler(net::io_context & io): ioc_{io} {}

    template <typename ... Params>
    auto register_worker(Params&&... params) -> std::pair<typename decltype(workers_)::iterator, bool>
    {
        return workers_.emplace(std::forward<Params>(params)...);
    }

    template <typename ... Params>
    auto launch(Params&&... params) -> boost::optional<std::string>
    {
        std::vector<std::pair<double, worker::worker*>> candidate;
        candidate.reserve(workers_.size());
        for (worker::worker& back : workers_)
            if (back.alive)
                candidate.emplace_back(back.load(), std::addressof(back));

        std::sort(candidate.begin(), candidate.end(), [](std::pair<double, worker::worker*> const &a,
                                                         std::pair<double, worker::worker*> const &b){
                                                          return a.first < b.first;
                                                      });
        for (std::pair<double, worker::worker*> const & pair : candidate)
            if (pair.second->alive)
            {
                pair.second->jobs++;
                SCOPE_DEFER([&pair]{ pair.second->jobs--; });
                boost::optional<std::string> result = send_request(*pair.second, std::forward<Params>(params)...);

                if (not result)
                    continue;
                return result;
            }
        return {};
    }

    auto send_request(worker::worker & back,
                      beast::string_view target,
                      beast::string_view fid,
                      beast::string_view client,
                      boost::json::object & val,
                      net::yield_context yield) -> boost::optional<std::string>
    {
        beast::error_code ec;

        val["target"] = target;
        val["functionid"] = fid;
        val["client"] = client;

        http::request<http::string_body> backreq {http::verb::get, target, 11};
        backreq.set(http::field::host, fid);
        backreq.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        backreq.set("argument", boost::json::serialize(val));

        BOOST_LOG_TRIVIAL(trace) << "scheduler backstream.async_connect\n";
        beast::tcp_stream backstream{ioc_};
        tcp::endpoint backendpoint(back.address, back.port);
        backstream.async_connect(backendpoint, yield[ec]);
        if (ec)
        {
            basic::fail(ec, "connect failed");
            back.alive = false;
            return {};
        }

        BOOST_LOG_TRIVIAL(trace) << "scheduler backstream.async_write\n";
        http::async_write(backstream, backreq, yield[ec]);
        if (ec)
        {
            basic::fail(ec, "write failed");
            back.alive = false;
            return {};
        }

        BOOST_LOG_TRIVIAL(trace) << "scheduler backstream.async_read\n";
        http::response<http::string_body> backres;
        beast::flat_buffer backbuffer;
        http::async_read(backstream, backbuffer, backres, yield[ec]);
        if (ec)
        {
            basic::fail(ec, "read failed");
            back.alive = false;
            return {};
        }
        return backres.body();
    }
};

} // namespace scheduler

} // namespace manager

#endif // FUNCSCHEDULER_HPP__
