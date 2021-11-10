#pragma once
#ifndef FUNCMANAGER_HPP__
#define FUNCMANAGER_HPP__

#include "basic.hpp"

#include <memory>
#include <iostream>

namespace manager
{

class http_server : public std::enable_shared_from_this<http_server>
{
    net::io_context & ioc_;

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
    http_server(net::io_context & io) : ioc_{io} {}

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
            http::response<http::string_body> res{http::status::ok, req.version()};
            res.body() = "An Hello world: " + std::string(req.target());
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "application/text");
            res.keep_alive(req.keep_alive());
            res.prepare_payload();
            return send(std::move(res));
        }
        case http::verb::post:
        {
            if (req[http::field::content_type] == "application/x-www-form-urlencoded" ||
                req[http::field::content_type] == "multipart/form-data")
            {
                //dynamic_body string_body
                http::request_parser<http::file_body> parser {std::move(reqparser)};
                beast::error_code ec;

                parser.body_limit(std::numeric_limits<std::uint64_t>::max());
                parser.get().body().open("/tmp/123.txt", boost::beast::file_mode::write, ec);
                http::async_read(stream, buffer, parser, yield[ec]);

                BOOST_LOG_TRIVIAL(trace) << "Writing to /tmp/123.txt \n";
                http::response<http::string_body> res{http::status::ok, req.version()};
                res.body() = "Accepted => "s + "/tmp/123.txt";
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
