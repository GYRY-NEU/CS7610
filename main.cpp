

// nodes shares same binary
// executer => ./run --register ip:port
// coordinator => ./run --listen port

#include "funcmanager.hpp"
#include "funcexecuter.hpp"
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
        ("storage,s",  po::value<std::string>()->default_value("function/"), "save zip functions at this place")

        ("execpath",   po::value<std::string>()->default_value("functionexec/"), "[worker] execute functions at this place")
        ("register,r", po::value<std::string>(), "[worker] register to this host 'ip:port'")

        ("listen,l",   po::value<unsigned short>()->default_value(12000), "[coordinator] listen on this port");
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

    int const worker = std::thread::hardware_concurrency();

    net::io_context ioc {worker};

    unsigned short const port = vm["listen"].as<unsigned short>();
    std::string const storage = vm["storage"].as<std::string>();

    BOOST_LOG_TRIVIAL(info) << "listen on " << port << "\n";
    if (vm.count("listen") and not vm.count("register"))
    {
        BOOST_LOG_TRIVIAL(info) << "Starting coordinator in " << boost::filesystem::current_path() << "\n";
        auto http = std::make_shared<manager::http_server>(ioc, storage);
        boost::asio::spawn(ioc,
                           [http=http->shared_from_this(), port] (net::yield_context yield) {
                               http->do_listen(tcp::endpoint{tcp::v4(), port}, yield);
                           });
    }
    else if (vm.count("register"))
    {
        BOOST_LOG_TRIVIAL(info) << "Starting worker in " << boost::filesystem::current_path() << "\n";

        std::string const execpath = vm["execpath"].as<std::string>();
        auto exec = std::make_shared<executer::executer>(ioc, storage, execpath);
        std::string const remote = vm["register"].as<std::string>();
        exec->register_master(remote, port);

        boost::asio::spawn(ioc,
                           [exec=exec->shared_from_this(), port] (net::yield_context yield) {
                               exec->do_listen(tcp::endpoint{tcp::v4(), port}, yield);
                           });
    }

    std::vector<std::thread> v;
    v.reserve(worker - 1);
    for(int i = 1; i < worker; i++)
        v.emplace_back([&ioc] { ioc.run(); });
    ioc.run();

    for (std::thread& th : v)
        th.join();

    return EXIT_SUCCESS;
}
