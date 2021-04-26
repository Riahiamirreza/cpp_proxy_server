
#ifndef CONFIG_READER_HPP
#define CONFIG_READER_HPP

#include <string>
#include <regex>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace pt = boost::property_tree;


class ConfigReader {

	public:

		ConfigReader(std::string file_name){
			pt::read_json(file_name, root);
		}
		
		template <typename Y>
		bool check_value(std::string key){
			
			if(root.get_optional<Y>(key).is_initialized())
				return true;
			return false;
		}

		template <typename T>
		std::vector<T> get_item(std::string key){

			std::vector<T> result;
			for(pt::ptree::value_type &element : root.get_child(key)){
				result.push_back(element.second.get_value<T>());
			}

			return result;
		}
		
		template <typename X>
		X get_(std::string key){
			
			return root.get<X>(key);
		}





	private:
		pt::ptree root;
};

#endif // CONFIG_READER_HPP
