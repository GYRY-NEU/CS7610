#pragma once
#ifndef FUNCMANAGER_HPP__
#define FUNCMANAGER_HPP__

#include "basic.hpp"
#include "funcworker.hpp"
#include "funcstorage.hpp"

#include <memory>
#include <iostream>

namespace manager
{

class http_server : public std::enable_shared_from_this<http_server>
{
    net::io_context & ioc_;
//    tbb::concurrent_unordered_multimap<boost::uuids::uuid, worker> workers_;
    tbb::concurrent_unordered_set<worker, hash<worker>> workers_;
    std::string const zip_storage_;
    storage::storage kvstore_;

    // Returns a bad request response
    template<typename Body, typename Allocator>
    auto http_bad_request(beast::string_view why,
                          http::request<Body, http::basic_fields<Allocator>>& req)
        -> http::response<http::string_body>
    {
        http::response<http::string_body> res{http::status::bad_request, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = std::string(why);
        res.prepare_payload();
        return res;
    }

    // Returns a server error response
    template<typename Body, typename Allocator>
    auto http_server_error(beast::string_view what,
                           http::request<Body, http::basic_fields<Allocator>>& req)
        -> http::response<http::string_body>
    {
        http::response<http::string_body> res{http::status::internal_server_error, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "An error occurred: '" + std::string(what) + "'";
        res.prepare_payload();
        return res;
    }

public:
    http_server(net::io_context & io, std::string const &path) :
        ioc_{io},
        zip_storage_(path)
    {
        boost::filesystem::create_directory(zip_storage_);
    }

    // Accepts incoming connections and launches the sessions
    void do_listen(tcp::endpoint endpoint,
                   net::yield_context yield)
    {
        beast::error_code ec;

        // Open the acceptor
        tcp::acceptor acceptor(ioc_);
        acceptor.open(endpoint.protocol(), ec);
        if (ec)
            return basic::fail(ec, "open");

        // Allow address reuse
        acceptor.set_option(net::socket_base::reuse_address(true), ec);
        if (ec)
            return basic::fail(ec, "set_option");

        // Bind to the server address
        acceptor.bind(endpoint, ec);
        if (ec)
            return basic::fail(ec, "bind");

        // Start listening for connections
        acceptor.listen(net::socket_base::max_listen_connections, ec);
        if (ec)
            return basic::fail(ec, "listen");

        for (;;)
        {
            tcp::socket socket(ioc_);
            acceptor.async_accept(socket, yield[ec]);

            BOOST_LOG_TRIVIAL(trace) << "async_accept\n";
            if (ec)
                basic::fail(ec, "accept");
            else
                boost::asio::spawn(
                    acceptor.get_executor(),
                    [this, s=beast::tcp_stream(std::move(socket))] (net::yield_context yield) mutable {
                        do_session(s, yield);
                    });
        }
    }

    // Handles an HTTP server connection
    void do_session(beast::tcp_stream& stream,
                    net::yield_context yield)
    {
        bool close = false;
        beast::error_code ec;

        // This buffer is required to persist across reads
        beast::flat_buffer buffer;

        // This lambda is used to send messages
        auto send = [&, yield] (auto&& msg) {
            // type(msg) == template<bool isRequest, class Body, class Fields>
            //              http::message<isRequest, Body, Fields>
            using message = typename std::remove_reference<decltype(msg)>::type;
            close = msg.need_eof();

            // We need the serializer here because the serializer requires
            // a non-const file_body, and the message oriented version of
            // http::write only works with const messages.
            http::serializer<message::is_request::value,
                             typename message::body_type,
                             typename message::fields_type> sr{msg};
            http::async_write(stream, sr, yield[ec]);
        };

        for (;;)
        {
            // Set the timeout.
            stream.expires_after(std::chrono::seconds(30));

            http::request_parser<http::empty_body> reqparser;
            reqparser.body_limit(std::numeric_limits<std::uint64_t>::max());
            http::async_read_header(stream, buffer, reqparser, yield[ec]);

            if (ec == http::error::end_of_stream)
                break;

            if (ec)
                return basic::fail(ec, "read");

            // Send the response
            handle_request(stream, buffer, std::move(reqparser), send, yield);
            if (ec)
                return basic::fail(ec, "write");

            if (close)
            {
                // This means we should close the connection, usually because
                // the response indicated the "Connection: close" semantic.
                break;
            }
        }

        // Send a TCP shutdown
        stream.socket().shutdown(tcp::socket::shutdown_send, ec);
    }

    // This function produces an HTTP response for the given
    // request. The type of the response object depends on the
    // contents of the request, so the interface requires the
    // caller to pass a generic lambda for receiving the response.
    template<typename Send>
    void handle_request(beast::tcp_stream& stream,
                        beast::flat_buffer& buffer,
                        http::request_parser<http::empty_body>&& reqparser,
                        Send&& send,
                        net::yield_context yield)
    {
        // Request path must be absolute and not contain "..".
        auto&& req = reqparser.get();
        beast::error_code ec;

        if (req.target().empty() ||
            req.target()[0] != '/' ||
            req.target().find("..") != beast::string_view::npos)
            return send(http_server_error("Illegal request-target", req));

        switch (req.method())
        {
        case http::verb::head:
        {
            http::response<http::empty_body> res{http::status::ok, req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "application/text");
            res.content_length(0);
            res.keep_alive(req.keep_alive());
            return send(std::move(res));
        }
        case http::verb::get:
        {
            using namespace basic::sswitcher;
            BOOST_LOG_TRIVIAL(trace) << "Get " << req.target() << "\n";

            switch (basic::sswitcher::hash(req.target()))
            {
            case "/function"_:
            {
                auto && [remotehost, remoteport] = basic::parse_host(req[http::field::host]);
                std::string const id (remotehost);
                std::string const full_path = zip_storage_ + id + ".zip";

                BOOST_LOG_TRIVIAL(info) << "sending function zip: " << id << "\n";

                http::file_body::value_type file;
                file.open(full_path.c_str(), beast::file_mode::read, ec);
                http::response<http::file_body> res{http::status::ok, req.version()};

                res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                res.set(http::field::content_type, "application/zip");
                res.body() = std::move(file);
                res.keep_alive(req.keep_alive());
                res.prepare_payload();
                return send(std::move(res));
            }
            case "/value"_:
            {
                auto && [remotehost, remoteport] = basic::parse_host(req[http::field::host]);
                std::string const id  (remotehost);
                std::string const key (req["key"]);

                BOOST_LOG_TRIVIAL(trace) << "sending [" << key << "] = " << kvstore_[key] << "\n";

                http::response<http::string_body> res{http::status::ok, req.version()};
                res.body() = boost::json::serialize(kvstore_[key]);
                res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                res.set(http::field::content_type, "application/json");
                res.keep_alive(req.keep_alive());
                res.prepare_payload();

                return send(std::move(res));
            }
            default:
            {
                for (auto it = workers_.begin(); it != workers_.end(); ++it)
                {
                    if (it->alive)
                    {
                        worker& back = *it;

                        http::request<http::string_body> backreq {http::verb::get, req.target(), req.version()};
                        backreq.set(http::field::host, req[http::field::host]);
                        backreq.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

                        boost::json::value jv = {
                            { "target", req.target() },
                            { "functionid", req[http::field::host] },
                            { "client", stream.socket().remote_endpoint().address().to_string() },
                            { "http", req.version() },
                        };

                        backreq.set("argument", boost::json::serialize(jv));

                        BOOST_LOG_TRIVIAL(trace) << "backstream.async_connect\n";
                        beast::tcp_stream backstream{ioc_};
                        tcp::endpoint backendpoint(back.address, back.port);
                        backstream.async_connect(backendpoint, yield[ec]);
                        if (ec)
                        {
                            basic::fail(ec, "connect failed");
                            it->alive = false;
                            continue;
                        }

                        BOOST_LOG_TRIVIAL(trace) << "backstream.async_write\n";
                        http::async_write(backstream, backreq, yield[ec]);
                        if (ec)
                        {
                            basic::fail(ec, "write failed");
                            it->alive = false;
                            continue;
                        }

                        BOOST_LOG_TRIVIAL(trace) << "backstream.async_read\n";
                        http::response<http::string_body> backres;
                        beast::flat_buffer backbuffer;
                        http::async_read(backstream, backbuffer, backres, yield[ec]);

                        if (ec)
                        {
                            basic::fail(ec, "read failed");
                            it->alive = false;
                            continue;
                        }

                        http::response<http::string_body> res{http::status::ok, req.version()};
                        res.body() = backres.body();
                        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                        res.set(http::field::content_type, "application/text");
                        res.keep_alive(req.keep_alive());
                        res.prepare_payload();
                        return send(std::move(res));
                    }
                }
                return send(http_server_error("No Executer found\n", req));
            }
            }
            return send(http_server_error("GET not handled\n", req));
        }
        case http::verb::put:
        {
            using namespace basic::sswitcher;
            BOOST_LOG_TRIVIAL(trace) << "Put " << req.target() << "\n";

            switch (basic::sswitcher::hash(req.target()))
            {
            case "/value"_:
            {
                auto && [remotehost, remoteport] = basic::parse_host(req[http::field::host]);
                std::string const id  (remotehost);

                http::request_parser<http::string_body> parser {std::move(reqparser)};
                beast::error_code ec;

                parser.body_limit(std::numeric_limits<std::uint64_t>::max());
                http::async_read(stream, buffer, parser, yield[ec]);

                BOOST_LOG_TRIVIAL(trace) << "Put " << parser.get().body() << "\n";
                boost::json::value v = boost::json::parse(parser.get().body());
                boost::json::object const& obj = v.as_object();

                std::string const key = boost::json::value_to<std::string>(obj.at("key"));
                BOOST_LOG_TRIVIAL(trace) << "Insert [" << key << "] = " << obj.at("value") << "\n";
                kvstore_[key] = obj.at("value");

                http::response<http::string_body> res{http::status::ok, req.version()};
                boost::json::value jv = {
                    { "status", "ok" },
                };
                res.body() = boost::json::serialize(jv);
                res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                res.set(http::field::content_type, "application/json");
                res.keep_alive(req.keep_alive());
                res.prepare_payload();

                return send(std::move(res));
            }
            case "/register"_:
            {
                http::request_parser<http::string_body> parser {std::move(reqparser)};
                beast::error_code ec;

                parser.body_limit(std::numeric_limits<std::uint64_t>::max());
                http::async_read(stream, buffer, parser, yield[ec]);
                boost::json::value v = boost::json::parse(parser.get().body());
                boost::json::object const& obj = v.as_object();

                auto && [it, ok] = workers_.emplace (
                    (obj.if_contains("host")?
                     boost::json::value_to<std::string>(obj.at("host")).c_str():
                     stream.socket().remote_endpoint().address().to_string().c_str()),
                    boost::json::value_to<int>(obj.at("port"))
                );
                it->alive = true;

                BOOST_LOG_TRIVIAL(info) << "Registered executer: " << *it << "\n";
                http::response<http::string_body> res{http::status::ok, req.version()};

                boost::json::value jv = {
                    { "status", "Registered" },
                };

                res.body() =boost::json::serialize(jv);
                res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                res.set(http::field::content_type, "application/json");
                res.keep_alive(req.keep_alive());
                res.prepare_payload();
                return send(std::move(res));
            }
            }
        }
        case http::verb::post:
        {
            if (req[http::field::content_type] == "application/x-www-form-urlencoded" ||
                req[http::field::content_type] == "multipart/form-data")
            {
                //dynamic_body string_body
                http::request_parser<http::file_body> parser {std::move(reqparser)};
                beast::error_code ec;

                boost::uuids::uuid id = basic::genuuid();
                std::string const name = zip_storage_ + boost::uuids::to_string(id) + ".zip";
                parser.body_limit(std::numeric_limits<std::uint64_t>::max());
                parser.get().body().open(name.data(), boost::beast::file_mode::write, ec);
                http::async_read(stream, buffer, parser, yield[ec]);

                http::response<http::string_body> res{http::status::ok, req.version()};

                res.body() = "Accepted => "s + boost::uuids::to_string(id) + "\n";
                res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                res.set(http::field::content_type, "application/text");
                res.keep_alive(req.keep_alive());
                res.prepare_payload();
                return send(std::move(res));
            }
        }
        default:
            BOOST_LOG_TRIVIAL(info) << "request " << req.method() << "not handled\n";
        }
        return send(http_bad_request("Unhandled HTTP-method", req));
    }

};

} // manager

#endif // FUNCMANAGER_HPP__
