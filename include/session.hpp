#include <cstdlib>
#include <iostream>
#include <string>
#include <memory>
#include <regex>
#include <utility>
#include <boost/asio.hpp>
#include <fstream>
#include "config_reader.hpp"
#include "logger.hpp"
#include "datalog.hpp"





using boost::asio::ip::tcp;

inline void write_log(int prefix, short verbose, short verbose_level, int session_id, const std::string& what, const std::string& error_message = "") {
	if (verbose > verbose_level) return;

	std::string session = "";
	if (session_id >= 0) { session += "session("; session += std::to_string(session_id); session += "): "; }

	if (prefix > 0)
	{
		std::cerr << (prefix == 1 ? "Error: " : "Warning: ") << session << what;
		if (error_message.size() > 0)
			std::cerr << ": " << error_message;
		std::cerr << std::endl;
	}
	else
	{ 
		std::cout << session << what;
		if (error_message.size() > 0)
			std::cout << ": " << error_message;
		std::cout << std::endl;
	}
}

class Session : public std::enable_shared_from_this<Session> {
	public:
		Session(tcp::socket in_socket, unsigned session_id, size_t buffer_size, short verbose ,std::vector<int> nports, 
					std::vector<std::string> nip, std::vector<std::string> ndomain, std::vector<std::string> niport, std::vector<std::string> rgx_)
			:
			in_socket_(std::move(in_socket)), 
			out_socket_(in_socket.get_executor()), 
			resolver(in_socket.get_executor()),
			in_buf_(buffer_size), 
			out_buf_(buffer_size), 
			session_id_(session_id),
			verbose_(verbose),
			nports_(nports),
			nip_(nip),
			ndomain_(ndomain),
			niport_(niport),
			nrgxdom_(rgx_)
	{
	}

		void start()
		{
			read_socks5_handshake();
		}

	private:

		void read_socks5_handshake()
		{
			auto self(shared_from_this());

			in_socket_.async_receive(boost::asio::buffer(in_buf_),
					[this, self](boost::system::error_code ec, std::size_t length)
					{
					if (!ec)
					{

						if (length < 3 || in_buf_[0] != 0x05)
						{
							write_log(1, 0, verbose_, session_id_, "SOCKS5 handshake request is invalid. Closing session.");
							return;
						}

						uint8_t num_methods = in_buf_[1];
						// Prepare request
						in_buf_[1] = 0xFF;

						// Only 0x00 - 'NO AUTHENTICATION REQUIRED' is now support_ed
						for (uint8_t method = 0; method < num_methods; ++method)
							if (in_buf_[2 + method] == 0x00) { in_buf_[1] = 0x00; break; }

						write_socks5_handshake();
					}
					else
						write_log(1, 0, verbose_, session_id_, "SOCKS5 handshake request", ec.message());

					});
		}

		void write_socks5_handshake()
		{
			auto self(shared_from_this());

			boost::asio::async_write(in_socket_, boost::asio::buffer(in_buf_, 2), // Always 2-byte according to RFC1928
					[this, self](boost::system::error_code ec, std::size_t length)
					{
					if (!ec)
					{	
					if (in_buf_[1] == 0xFF) return; // No appropriate auth method found. Close session.
					read_socks5_request();
					}
					else
					write_log(1, 0, verbose_, session_id_, "SOCKS5 handshake response write", ec.message());

					});
		}

		void read_socks5_request()
		{
			auto self(shared_from_this());

			in_socket_.async_receive(boost::asio::buffer(in_buf_),
					[this, self](boost::system::error_code ec, std::size_t length)
					{
					if (!ec)
					{
						if (length < 5 || in_buf_[0] != 0x05 || in_buf_[1] != 0x01)
						{
							write_log(1, 0, verbose_, session_id_, "SOCKS5 request is invalid. Closing session.");
							return;
						}

						uint8_t addr_type = in_buf_[3], host_length;

						switch (addr_type)
						{
							case 0x01: // IP V4 addres
								{
									if (length != 10) { write_log(1, 0, verbose_, session_id_, "SOCKS5 request length is invalid. Closing session."); return; }
									remote_host_ = boost::asio::ip::address_v4(ntohl(*((uint32_t*)&in_buf_[4]))).to_string();
									remote_port__ = ntohs(*((uint16_t*)&in_buf_[8]));
									//std::string remote_port__ = std::to_string(ntohs(*((uint16_t*)&in_buf_[8])));
									remote_port_ = std::to_string(remote_port__);
									if(!check_allow_port(remote_port__)) { data_log.filtered_packets++             ; return; }
									if(!check_allow_ip(remote_host_)) {data_log.filtered_packets++                 ; return; }
									if(!check_allow_iport(remote_host_,remote_port__)){ data_log.filtered_packets++; return; }
									if(!check_allow_domain(remote_host_, true)){ data_log.filtered_packets++       ; return; }
									if(!check_allow_domain_regex(remote_host_)){ data_log.filtered_packets++       ; return; }
								}

								break;
							case 0x03: // DOMAINNAME
								host_length = in_buf_[4];
								if (length != (size_t)(5 + host_length + 2)) { write_log(1, 0, verbose_, session_id_, "SOCKS5 request length is invalid. Closing session."); return; }
								remote_host_ = std::string(&in_buf_[5], host_length);
								remote_port_ = std::to_string(ntohs(*((uint16_t*)&in_buf_[5 + host_length])));
								break;
							default:
								write_log(1, 0, verbose_, session_id_, "unsupport_ed address type in SOCKS5 request. Closing session.");
								break;
						}

						do_resolve();
					}
					else
						write_log(1, 0, verbose_, session_id_, "SOCKS5 request read", ec.message());

					});
		}

		void do_resolve()
		{
			auto self(shared_from_this());

			resolver.async_resolve(tcp::resolver::query({ remote_host_, remote_port_ }),
					[this, self](const boost::system::error_code& ec, tcp::resolver::iterator it)
					{
					if (!ec)
					{
					do_connect(it);
					}
					else
					{
					std::ostringstream what; what << "failed to resolve " << remote_host_ << ":" << remote_port_;
					write_log(1, 0, verbose_, session_id_, what.str(), ec.message());
					}
					});
		}

		void do_connect(tcp::resolver::iterator& it)
		{
			auto self(shared_from_this());
			out_socket_.async_connect(*it, 
					[this, self](const boost::system::error_code& ec)
					{
					if (!ec)
					{
					std::ostringstream what; what << "connected to " << remote_host_ << ":" << remote_port_;
					write_log(0, 1, verbose_, session_id_, what.str());
					write_socks5_response();
					}
					else
					{
					std::ostringstream what; what << "failed to connect " << remote_host_ << ":" << remote_port_;
					write_log(1, 0, verbose_, session_id_, what.str(), ec.message());

					}
					});

		}

		void write_socks5_response()
		{
			auto self(shared_from_this());

			in_buf_[0] = 0x05; in_buf_[1] = 0x00; in_buf_[2] = 0x00; in_buf_[3] = 0x01;
			uint32_t realRemoteIP = out_socket_.remote_endpoint().address().to_v4().to_ulong();
			uint16_t realRemoteport = htons(out_socket_.remote_endpoint().port());

			std::memcpy(&in_buf_[4], &realRemoteIP, 4);
			std::memcpy(&in_buf_[8], &realRemoteport, 2);

			boost::asio::async_write(in_socket_, boost::asio::buffer(in_buf_, 10), // Always 10-byte according to RFC1928
					[this, self](boost::system::error_code ec, std::size_t length)
					{
					if (!ec)
					{
					do_read(3); // Read both sockets
					}
					else
					write_log(1, 0, verbose_, session_id_, "SOCKS5 response write", ec.message());
					});
		}


		void do_read(int direction)
		{
			auto self(shared_from_this());
			data_log.sc_packets++;

			// We must divide reads by direction to not permit second read call on the same socket.
			if (direction & 0x1)
				in_socket_.async_receive(boost::asio::buffer(in_buf_),
						[this, self](boost::system::error_code ec, std::size_t length)
						{
						if (!ec)
						{
						data_log.sc_size_byte += length; 
						std::ostringstream what; what << "--> " << std::to_string(length) << " bytes";
						write_log(0, 2, verbose_, session_id_, what.str());

						do_write(1, length);
						}
						else //if (ec != boost::asio::error::eof)
						{
						write_log(2, 1, verbose_, session_id_, "closing session. Client socket read error", ec.message());
						// Most probably client closed socket. Let's close both sockets and exit session.
						in_socket_.close(); out_socket_.close();
						data_log.deactived_sessions++;
						data_log.active_sessions--;
						}

						});

			if (direction & 0x2)
				out_socket_.async_receive(boost::asio::buffer(out_buf_),
						[this, self](boost::system::error_code ec, std::size_t length)
						{
						if (!ec)
						{
						data_log.sc_size_byte += length; 
						std::ostringstream what; what << "<-- " << std::to_string(length) << " bytes";
						write_log(0, 2, verbose_, session_id_, what.str());

						do_write(2, length);
						}
						else //if (ec != boost::asio::error::eof)
						{
						write_log(2, 1, verbose_, session_id_, "closing session. Remote socket read error", ec.message());
						// Most probably remote server closed socket. Let's close both sockets and exit session.
						in_socket_.close(); out_socket_.close();
						//data_log.deactived_sessions++;
						//data_log.active_sessions--;
						}
						});
		}

		void do_write(int direction, std::size_t Length)
		{
			auto self(shared_from_this());
			data_log.sc_packets++;
			switch (direction)
			{
				case 1:
					boost::asio::async_write(out_socket_, boost::asio::buffer(in_buf_, Length),
							[this, self, direction](boost::system::error_code ec, std::size_t length)
							{
							if (!ec)
							do_read(direction);
							else
							{
							write_log(2, 1, verbose_, session_id_, "closing session. Client socket write error", ec.message());
							// Most probably client closed socket. Let's close both sockets and exit session.
							in_socket_.close(); out_socket_.close();
							}
							});
					break;
				case 2:
					boost::asio::async_write(in_socket_, boost::asio::buffer(out_buf_, Length),
							[this, self, direction](boost::system::error_code ec, std::size_t length)
							{
							if (!ec)
							do_read(direction);
							else
							{
							write_log(2, 1, verbose_, session_id_, "closing session. Remote socket write error", ec.message());
							// Most probably remote server closed socket. Let's close both sockets and exit session.
							in_socket_.close(); out_socket_.close();
							}
							});
					break;
			}
		}

		bool check_allow_ip(std::string ip){

			if(std::find(nip_.begin(), nip_.end(), ip) != nip_.end())
				return false;
			return true;
		}

		bool check_allow_port(int port){

			if(std::find(nports_.begin(), nports_.end(), port) != nports_.end())
				return false;
			return true;
		}


		bool check_allow_domain(std::string domain, bool is_ip){
			
			if(is_ip){
				std::string domain__ = reverse_dns();				
				if(std::find(ndomain_.begin(), ndomain_.end(), domain__) != ndomain_.end())
					return false;

				return true;
			}
					
			if(std::find(ndomain_.begin(), ndomain_.end(), domain) != ndomain_.end())
				return false;
	
			return true;
			
		}
		
		bool check_allow_domain_regex(std::string pattern){
			
			for(std::string it: nrgxdom_)
				if (std::regex_match(pattern ,std::regex(it)))
					return false;
			return true;
		}


		bool check_allow_iport(std::string ip, int port){
			
			if(std::find(niport_.begin(), niport_.end(), ip + ":" + std::to_string(port)) != niport_.end())
				return false; 
	
			return true;
		}

		std::string reverse_dns(){

			//boost::asio::ip::tcp::endpoint ep;
			//ep = boost::asio::ip::address::from_string(remote_host_);
			boost::asio::ip::tcp::endpoint ep(boost::asio::ip::address::from_string(remote_host_), remote_port__);
			boost::asio::ip::tcp::resolver::iterator itr = resolver.resolve(ep);
			boost::asio::ip::tcp::resolver::iterator end;
			
			//for (int i = 1; itr != end; itr++, i++)
			//	std::cout << "hostname #" << i << ": " << itr->host_name() << '\n';
			
			return itr->host_name();

		}

		tcp::socket in_socket_;
		tcp::socket out_socket_;
		tcp::resolver resolver;

		std::string remote_host_;
		std::string remote_port_;
		std::vector<char> in_buf_;
		std::vector<char> out_buf_;


		int session_id_;
		short verbose_;

		std::vector<int> nports_          ; // a list of not allowed ports.
		std::vector<std::string> nip_     ; // a list of not allowed ips. 
		std::vector<std::string> ndomain_ ;
		std::vector<std::string> niport_  ;
		std::vector<std::string> nrgxdom_ ;
		int remote_port__;
};
