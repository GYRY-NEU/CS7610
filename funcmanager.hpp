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
        auto send = [&, yield]<bool isRequest, class Body, class Fields>
            (http::message<isRequest, Body, Fields>&& msg) {
            close = msg.need_eof();

            // We need the serializer here because the serializer requires
            // a non-const file_body, and the message oriented version of
            // http::write only works with const messages.
            http::serializer<isRequest, Body, Fields> sr{msg};
            http::async_write(stream, sr, yield[ec]);
        };

        for (;;)
        {
            // Set the timeout.
            stream.expires_after(std::chrono::seconds(30));

            // Read a request
            http::request<http::string_body> req;
            http::async_read(stream, buffer, req, yield[ec]);

            if (ec == http::error::end_of_stream)
                break;

            if (ec)
                return basic::fail(ec, "read");

            // Send the response
            handle_request(std::move(req), send);
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

        // At this point the connection is closed gracefully
    }

    // This function produces an HTTP response for the given
    // request. The type of the response object depends on the
    // contents of the request, so the interface requires the
    // caller to pass a generic lambda for receiving the response.
    template<typename Body, typename Allocator, typename Send>
    void handle_request(http::request<Body, http::basic_fields<Allocator>>&& req,
                        Send&& send)
    {
        // Make sure we can handle the method
        if (req.method() != http::verb::get &&
            req.method() != http::verb::head)
            return send(http_bad_request("Unknown HTTP-method", req));

        // Request path must be absolute and not contain "..".
        if (req.target().empty() ||
            req.target()[0] != '/' ||
            req.target().find("..") != beast::string_view::npos)
            return send(http_server_error("Illegal request-target", req));

        // Respond to HEAD request
        if (req.method() == http::verb::head)
        {
            http::response<http::empty_body> res{http::status::ok, req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "application/text");
            res.content_length(0);
            res.keep_alive(req.keep_alive());
            return send(std::move(res));
        }

        // Respond to GET request
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.body() = "An Hello world: " + std::string(req.target());
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/text");
        res.keep_alive(req.keep_alive());
        res.prepare_payload();
        return send(std::move(res));
    }

};

} // manager

#endif // FUNCMANAGER_HPP__
