#include <iostream>
#include <map>
#include <vector>
#include <sstream>      // std::istringstream
#include <fstream>
#include <string>       // std::string
using namespace std;


vector<string> split(const string& s, char delimiter);
void print_vector(vector<string> v);

// Seperates given string into partial strings stored in a vector based on delimiter character
vector<string> split(const string& str, char delimiter)
{
   vector<string> split_str;
   string token;
   istringstream tokenStream(str);
   while (getline(tokenStream, token, delimiter))
   {
   		split_str.push_back(token);
   }
   return split_str;
}

void print_vector(vector<string> v) {
	cout << v.size() << endl;
	for (auto const &c : v) {
		cout << c << endl;
	}
}

//Firewall Class
// CheckIPRange ensures that the packets' IP is within acceptable range
// CheckPortRange ensures that Packets' IP is withing acceptable range

class Firewall {
	private:
		bool checkIpRange(vector<string> range, string ip_value);
		bool checkPortRange(vector<string> range, int port);
	public:
		string filepath;
		map<string, vector< vector <string> > > rulesMap;
		Firewall(string filepath);
		bool accept_packet(string direction, string protocol, int port, string ip_address);
};

Firewall::Firewall(string path) {
	filepath = path;
	ifstream ruleFile(path);
	string line;
	while(getline(ruleFile, line, '\n')) {
		vector<string> rule = split(line, ',');
		string ruleKey = rule[0]+rule[1];
		//No entry exists for that hash
		if(rulesMap.find(ruleKey) == rulesMap.end()) {
			vector< vector <string> > allRules;
			allRules.push_back(rule);
			rulesMap[ruleKey] = allRules;
		} else {
			rulesMap[ruleKey].push_back(rule);
		}
	}
}


// Check if given IP is in range between lower and upper bound found in rules
bool Firewall::checkIpRange(vector<string> range, string ip_value) {
	vector<string> lower_range = split(range[0], '.');
	vector<string> upper_range = split(range[1], '.');
	vector<string> value_range = split(ip_value, '.');
	for(int i = 0; i < lower_range.size(); i++) {
		if(stoi(value_range[i]) >= stoi(lower_range[i]) && stoi(value_range[i]) <= stoi(upper_range[i]))
			continue;
		else
			return false;
	}
	return true;
}

// Check if Given PORT is within the port range of Packet under ivestigation
bool Firewall::checkPortRange(vector<string> range, int port) {
	string lower_range = range[0];
	string upper_range = range[1];
	return port >= stoi(lower_range) && port <= stoi(upper_range);
}


bool Firewall::accept_packet(string direction, string protocol, int pt, string ip_addr) {
	string key = direction + protocol;							// 
	vector< vector <string> > allRules = this->rulesMap[key];
	for (auto const &rule : allRules) {
		string port = rule[2];
		string ip_address = rule[3];
		if(ip_address.find('-') != std::string::npos) {
			vector<string> temp_ip_range = split(ip_address, '-');
			if(!checkIpRange(temp_ip_range, ip_addr)) {
				return false;
			}
		} 
		else if(ip_address.compare(ip_addr)) {
			return false;
		}
		if(port.find('-') != std::string::npos) {
			vector<string> temp_port_range = split(port, '-');
			if(!checkPortRange(temp_port_range, pt)) {
				return false;
			}
		} 
		else if(stoi(port) != pt) {
				return false;		
		}
	}
	return true;
}

int main() {
	Firewall fw("firewall.csv");
	cout << fw.accept_packet("inbound", "tcp", 80, "192.168.1.2") << endl;
	cout << fw.accept_packet("inbound", "udp", 53, "192.168.2.1") << endl;
	cout << fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11") << endl;
	cout << fw.accept_packet("inbound", "tcp", 81, "192.168.1.2") << endl;
	cout << fw.accept_packet("inbound", "udp", 24, "52.12.48.92") << endl;
	return 0;
}



