
//------------------------------------------------------------------------------
//
// Example: HTTP server, coroutine
//
//------------------------------------------------------------------------------

// nodes shares same binary
// executer => ./run --register ip:port
// coordinator => ./run --listen port

#include "funcmanager.hpp"
#include "basic.hpp"

#include <boost/program_options.hpp>
#include <boost/log/trivial.hpp>

#include <algorithm>
#include <cstdlib>
#include <iostream>

#include <memory>
#include <string>
#include <thread>
#include <vector>

int main(int argc, char* argv[])
{
    basic::init_log();

    namespace po = boost::program_options;
    po::options_description desc{"Options"};
    desc.add_options()
        ("help,h", "Print this help messages")
        ("register,r", po::value<std::string>(), "[executer] register to this host ip:port")
        ("listen,l",   po::value<unsigned short>(), "[coordinator] listen on this port");
    po::positional_options_description pos_po;
    po::variables_map vm;
    po::store(po::command_line_parser(argc, argv)
              .options(desc)
              .positional(pos_po).run(), vm);
    po::notify(vm);

    if (vm.count("help"))
    {
        BOOST_LOG_TRIVIAL(info) << desc << "\n";
        return EXIT_FAILURE;
    }

    if (vm.count("listen") + vm.count("register") == 0)
    {
        BOOST_LOG_TRIVIAL(fatal) << "please use --register or --listen to set the mode\n";
        return EXIT_FAILURE;
    }

    int const worker = std::thread::hardware_concurrency();

    net::io_context ioc {worker};

    if (vm.count("listen"))
    {
        unsigned short const port = vm["listen"].as<unsigned short>();
        BOOST_LOG_TRIVIAL(info) << "listen on " << port << "\n";

        auto http = std::make_shared<manager::http_server>(ioc);
        boost::asio::spawn(ioc,
                           [http=http->shared_from_this(), port] (net::yield_context yield) {
                               http->do_listen(tcp::endpoint{tcp::v4(), port}, yield);
                           });
    }
    else if (vm.count("register"))
    {

    }

    std::vector<std::thread> v;
    v.reserve(worker - 1);
    for(int i = 1; i < worker; i++)
        v.emplace_back([&ioc] { ioc.run(); });
    ioc.run();

    return EXIT_SUCCESS;
}
