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
    tcp::endpoint master_addr_;

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
    executer(net::io_context & io,
             std::string const& zip,
             std::string const& exec):
        ioc_{io},
        zip_storage_(zip),
        execute_path_(exec)
    {
        boost::filesystem::create_directory(zip_storage_);
        boost::filesystem::create_directory(execute_path_);
    }

    void register_master(std::string const& remote, unsigned short const port)
    {
        auto && [remotehost, remoteport] = basic::parse_host(remote);
        BOOST_LOG_TRIVIAL(trace) << "register to " << remotehost << ":" << remoteport << "\n";

        beast::tcp_stream stream{ioc_};
        master_addr_ = tcp::endpoint(net::ip::make_address(remotehost.c_str()), remoteport);
        stream.connect(master_addr_);

        http::request<http::string_body> req{http::verb::put, "/", 11};
        req.set(http::field::host, remotehost);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        boost::json::value jv = {
//            { "host", remotehost },
            { "port", port },
        };
        BOOST_LOG_TRIVIAL(trace) << "register: " << jv << "\n";
        req.body() = boost::json::serialize(jv);
        req.prepare_payload();

        http::write(stream, req);
    }

    void getfunc(std::string const& funcid,
                 net::yield_context yield)
    {
        beast::tcp_stream stream{ioc_};
        beast::error_code ec;
        stream.async_connect(master_addr_, yield[ec]);
        if (ec)
            return basic::fail(ec, "get func async_connect");

        http::request<http::string_body> req{http::verb::get, "/get-function", 11};
        req.set(http::field::host, funcid);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        BOOST_LOG_TRIVIAL(trace) << "get func " << funcid << "\n";
        req.body() = "";
        req.prepare_payload();

        http::async_write(stream, req, yield[ec]);
        if (ec)
            return basic::fail(ec, "get func send req");

        http::response_parser<http::file_body> parser;
        beast::flat_buffer buffer;
        std::string const name = zip_storage_ + funcid + ".zip";
        parser.get().body().open(name.data(), boost::beast::file_mode::write, ec);
        if (ec)
            return basic::fail(ec, "get func open local file");

        http::async_read(stream, buffer, parser, yield[ec]);
        if (ec)
            return basic::fail(ec, "get func get file");
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
            std::string host(req[http::field::host]);
            std::string const json_argument(req["argument"]);

            std::size_t const trim_pos = host.find(":");
            if (trim_pos != host.npos)
                host = host.substr(0, trim_pos);

            std::string const name = zip_storage_ + host + ".zip";

            BOOST_LOG_TRIVIAL(trace) << "Extracting " << name << " \n";
            if (not boost::filesystem::exists(name))
            {
                BOOST_LOG_TRIVIAL(trace) << "File not found. " << name << ". Getting from master \n";
                getfunc(host, yield);
            }

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
                        bp::args({"-c", "from main import main; main('"s + json_argument + "')"}),
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
