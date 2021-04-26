#include <boost/log/trivial.hpp>


class Logger{
	
	public:
		Logger(){}

		void set_loglevel(int loglevel_){
			
			loglevel = loglevel_;
		}
		
		void log(int severity,const std::string& message){
			
			switch(severity){
				case 0:
					BOOST_LOG_TRIVIAL(fatal) << message;
					break;
				case 1:
					BOOST_LOG_TRIVIAL(error) << message;
					break;
				case 2:
					BOOST_LOG_TRIVIAL(warning) << message;
					break;
				case 3:
					BOOST_LOG_TRIVIAL(info) << message;
					break;
				case 4:
					BOOST_LOG_TRIVIAL(debug) << message;
					break;
				case 5:
					BOOST_LOG_TRIVIAL(trace) << message;
					break;
			
			}
			
		}		

	private:
		int loglevel = 3;

};
