
#include "include/server.hpp"

int main(int argc, char* argv[]) {

	short verbose = 1;
	short port = 2121;
	size_t buffer_size = 8192;

	std::vector<int> block_port            ;
	std::vector<std::string> block_ip      ;
	std::vector<std::string> block_domain  ;
	std::vector<std::string> block_patterns;
	std::vector<std::string> block_ep      ;

	try{
		if (argc != 2) {
			std::cout << "Usage: boost_socks5 <config_file>" << std::endl;
			return 1;
		}

		ConfigReader conf(argv[1]);

		if(conf.check_value<std::string>("log level"))
			verbose        = conf.get_<int>("log level");
		
		if(conf.check_value<std::string>("block ports"))
			block_port     = conf.get_item<int>("block ports");
		
		if(conf.check_value<std::string>("block ip"))
			block_ip       = conf.get_item<std::string>("block ip");
		
		if(conf.check_value<std::string>("block domains"))
			block_domain   = conf.get_item<std::string>("block domains");

		if(conf.check_value<std::string>("block patterns"))
			block_patterns = conf.get_item<std::string>("block patterns");
	
		if(conf.check_value<std::string>("bock ip:port"))
			block_domain   = conf.get_item<std::string>("bock ip:port");


		boost::asio::io_service io_service;
		Server server(io_service, port, buffer_size, verbose, block_port, block_ip, block_domain, block_ep, block_patterns);
		io_service.run();

	} catch (std::exception& e) {
		write_log(1, 0, verbose, -1, "", e.what());
	} catch (...) {
		write_log(1, 0, verbose, -1, "", "exception...");
	}

	return 0;
}
