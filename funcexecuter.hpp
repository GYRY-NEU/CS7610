#pragma once
#ifndef FUNCEXECUTER_HPP__
#define FUNCEXECUTER_HPP__

#include "basic.hpp"

namespace executer
{

class executer : public std::enable_shared_from_this<executer>
{
    net::io_context & ioc_;
    std::string const zip_storage_;
    std::string const execute_path_;

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

public:
    executer(net::io_context & io, std::string const& zip, std::string const& exec):
        ioc_{io},
        zip_storage_(zip),
        execute_path_(exec)
    {
        boost::filesystem::create_directory(zip_storage_);
        boost::filesystem::create_directory(execute_path_);
    }

    void do_listen(tcp::endpoint endpoint,
                   net::yield_context yield)
    {
        beast::error_code ec;

        tcp::acceptor acceptor(ioc_);
        acceptor.open(endpoint.protocol(), ec);
        if (ec)
            return basic::fail(ec, "open");

        acceptor.set_option(net::socket_base::reuse_address(true), ec);
        if (ec)
            return basic::fail(ec, "set_option");

        acceptor.bind(endpoint, ec);
        if (ec)
            return basic::fail(ec, "bind");

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

    void do_session(beast::tcp_stream& stream,
                    net::yield_context yield)
    {
        bool close = false;
        beast::error_code ec;
        beast::flat_buffer buffer;


        auto send = [&, yield] (auto&& msg) {
            using message = typename std::remove_reference<decltype(msg)>::type;
            close = msg.need_eof();

            http::serializer<message::is_request::value,
                             typename message::body_type,
                             typename message::fields_type> sr{msg};
            http::async_write(stream, sr, yield[ec]);
        };

        for (;;)
        {
            stream.expires_after(std::chrono::seconds(30));

            http::request_parser<http::empty_body> reqparser;
            reqparser.body_limit(std::numeric_limits<std::uint64_t>::max());
            http::async_read_header(stream, buffer, reqparser, yield[ec]);

            if (ec == http::error::end_of_stream)
                break;

            if (ec)
                return basic::fail(ec, "read");

            handle_request(stream, buffer, std::move(reqparser), send, yield);
            if (ec)
                return basic::fail(ec, "write");

            if (close)
                break;
        }

        stream.socket().shutdown(tcp::socket::shutdown_send, ec);
    }

    template<typename Send>
    void handle_request(beast::tcp_stream& stream,
                        beast::flat_buffer& buffer,
                        http::request_parser<http::empty_body>&& reqparser,
                        Send&& send,
                        net::yield_context yield)
    {
        auto&& req = reqparser.get();
        switch (req.method())
        {
        case http::verb::get:
        {
            std::string host(req[http::field::host]);
            std::size_t const trim_pos = host.find(":");
            if (trim_pos != host.npos)
                host = host.substr(0, trim_pos);

            std::string const name = zip_storage_ + host + ".zip";

            BOOST_LOG_TRIVIAL(trace) << "Extracting " << name << " \n";
            std::string const fwd = execute_path_ + host + "/";
            boost::filesystem::create_directory(fwd);

            libzippp::ZipArchive zf(name);
            zf.open(libzippp::ZipArchive::ReadOnly);
            SCOPE_DEFER ([&zf] { zf.close(); });

            for (libzippp::ZipEntry& entry : zf.getEntries())
            {
                std::string const zipname = fwd + entry.getName();
                std::size_t const zipsize = entry.getSize();
                std::ofstream output(zipname, std::ios::out | std::ios::binary);

                char const* binary = static_cast<char const*>(entry.readAsBinary());
                BOOST_LOG_TRIVIAL(trace) << "Extract to " << zipname << " \n";
                output.write(binary, zipsize);
            }

            bp::async_pipe ap{ioc_};

            bp::child c(bp::search_path("python3"),
                        bp::start_dir = fwd,
                        bp::args({"-c", "from main import main; main()"}),
                        bp::std_out > ap);
            std::string body;
            std::array<char, 4096> buf;
            beast::error_code ec;

            for (;;)
            {
                std::size_t length = ap.async_read_some(boost::asio::buffer(buf), yield[ec]);
                BOOST_LOG_TRIVIAL(trace) << "read from python size: " << length << "\n";
                body.append(buf.data(), length);

                if (ec)
                {
                    if (ec != boost::asio::error::eof)
                        BOOST_LOG_TRIVIAL(error) << "error reading child " << ec.message() << "\n";
                    break;
                }
            }
            c.wait();

            http::response<http::string_body> res{http::status::ok, req.version()};

            res.body() = body;
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "application/text");
            res.keep_alive(req.keep_alive());
            res.prepare_payload();
            return send(std::move(res));
        }
        default:
            BOOST_LOG_TRIVIAL(info) << "request " << req.method() << "not handled\n";
        }
        return send(http_bad_request("Unhandled HTTP-method", req));
    }
};

} // namespace executer

#endif // FUNCEXECUTER_HPP__
