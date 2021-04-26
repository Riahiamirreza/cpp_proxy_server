#include "session.hpp"
#include <thread>
#include <mutex>
#include <chrono>

class Server {
	public:
		Server(boost::asio::io_service& io_service, short port, unsigned buffer_size, short verbose, 
			std::vector<int> ports, std::vector<std::string> ip, std::vector<std::string> domain, std::vector<std::string> ipo, std::vector<std::string> rgxd_)
			: acceptor_(io_service, tcp::endpoint(tcp::v4(), port)), 
			in_socket_(io_service), buffer_size_(buffer_size), verbose_(verbose), session_id_(0), nport(ports), nip(ip), 
			ndom(domain), nipo(ipo), nrgxd(rgxd_)
		{
			std::thread log_thread(&Server::log_, this);
			do_accept();
			log_thread.detach();
		}

	private:
		void do_accept()
		{
			acceptor_.async_accept(in_socket_,
					[this](boost::system::error_code ec)
					{
					if (!ec)
					{
					data_log.active_sessions++;
					data_log.new_sessions++;
					std::make_shared<Session>(std::move(in_socket_), session_id_++, buffer_size_, verbose_, nport, nip, ndom, nipo, nrgxd)->start();
					}
					else
					write_log(1, 0, verbose_, session_id_, "socket accept error", ec.message());

					do_accept();
					});
		}
		
		void log_(){
			
			std::mutex mtx;
			
			for(;;){
				
				std::this_thread::sleep_for(std::chrono::seconds(60));
				mtx.lock();
				log__();
				data_log.new_sessions = 0;
				mtx.unlock();
			}
		}
		
		void log__(){

			Logger lg;
			std::string message = "\n"                        	                                             ;
			std::string b =  "\033[7;37m"                                                                        ; 
			std::string s =  "\033[0m"                                                                           ; 
			message += b + "packets sent and received : " + s + std::to_string(data_log.sc_packets)        + "\n";
			message += b + "packets dropped           : " + s + std::to_string(data_log.filtered_packets)  + "\n"; 
			message += b + "active sessions           : " + s + std::to_string(data_log.active_sessions)   + "\n";
			message += b + "new sessions              : " + s + std::to_string(data_log.new_sessions)      + "\n";
			message += b + "closed sessions           : " + s + std::to_string(data_log.deactived_sessions)+ "\n";
			message += b + "size transmitted          : " + s + std::to_string(data_log.sc_size_byte)      + "\n";

			lg.log(3,message);
		}

		tcp::acceptor acceptor_;
		tcp::socket in_socket_;
		size_t buffer_size_;
		short verbose_;
		unsigned session_id_;
		std::vector<int> nport;
		std::vector<std::string> nip;
		std::vector<std::string> ndom;
		std::vector<std::string> nipo;
		std::vector<std::string> nrgxd;


};



