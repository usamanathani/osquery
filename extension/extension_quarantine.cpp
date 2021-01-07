// Note 1: Include the sdk.h helper.
/*
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/logger/logger.h> */

#include <osquery/system.h>
#include <osquery/tables.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/logger.h>


#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

#include <fstream>
#include <stdio.h>  
#include <vector>
#include <sstream>

#ifdef _WIN32 // FileExists, access
   #include <io.h> 
   #define access    _access_s
#else
   #include <unistd.h>
#endif


// Note 2: Define at least one plugin or table.
class SeceonTable : public osquery::TablePlugin {
 private:
    /// Simple primary key implementation; this is just the two columns
  /// concatenated
  using PrimaryKey = std::string;

  /// A rowid value uniquely identifies a row in a table
  using RowID = std::string;

  /// Data mutex
  std::mutex mutex;

  /// This is our data; each row contains a rowid, and the columns
  /// ('firewall')
  std::unordered_map<PrimaryKey, osquery::Row> data;

  /// This is used to map rowids to primary keys
  std::unordered_map<RowID, PrimaryKey> rowid_to_primary_key;
  // Global variables used for Firewall Quarantine and Revert Quarantine
  std::string firewall_export_location = "/tmp/";
  std::string netsh_location = "C:\\Windows\\System32\\netsh.exe";
  std::string osquery_path = "\"%ProgramFiles%\\osquery\\osqueryd\\osqueryd.exe\""; 
  
  /// This is an example implementation for a basic primary key
  PrimaryKey getPrimaryKey(const osquery::Row& row) const {
    return row.at("firewall");
  }

  /// Returns true if the given primary key is unique; used to adhere to
  /// constraints
  bool isPrimaryKeyUnique(
      const PrimaryKey& primary_key,
      const std::string& ignored_rowid = std::string()) const {
    auto it = data.find(primary_key);
    if (it == data.end()) {
      return true;
    }

    if (ignored_rowid.empty()) {
      return false;
    }

    return it->second.at("rowid") == ignored_rowid;
  }

  /// Generates a new rowid value; used when sqlite3 does not provide one
  size_t generateRowId() const {
    static size_t rowid_generator = 0U;
    return rowid_generator++;
  }

  /// Saves the given row
  osquery::Status saveRow(const osquery::Row& row, PrimaryKey primary_key = std::string()) {
    // Expect full rows (i.e. must include the rowid column)
    if (row.size() != 3U) {
      return osquery::Status(1, "Invalid column count");
    }

    // Compute the primary key if we haven't received one
    if (primary_key.empty()) {
      primary_key = getPrimaryKey(row);
    }

    // Save the row and update the index
    data.insert({primary_key, row});

    const auto& rowid = row.at("rowid");
    rowid_to_primary_key.insert({rowid, primary_key});

    return osquery::Status::success();
  }

  /// Expands a value list returned by osquery into a Row (without the rowid
  /// column)
  osquery::Status getRowData(osquery::Row& row, const std::string& json_value_array) const {
    row.clear();

    rapidjson::Document document;
    document.Parse(json_value_array);
    if (document.HasParseError() || !document.IsArray()) {
      return osquery::Status(1, "Invalid format");
    }

    if (document.Size() != 2U) {
      return osquery::Status(1, "Wrong column count");
    }

    row["firewall"] = document[0].IsNull() ? "" : document[0].GetString();    

    return osquery::Status::success();
  }

 /*
  using PrimaryKey = std::string;
  using RowID = std::uint64_t;
  using RowIdToPrimaryKeyMap = std::unordered_map<RowID, PrimaryKey>;

  RowID SeceonTable::GenerateRowID() {
    static std::uint64_t generator = 0U;

    generator = (generator + 1) & 0x7FFFFFFFU;
    return generator;
  }
  */

  osquery::TableColumns columns() const override {
    return {
      std::make_tuple("firewall", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
      //std::make_tuple("seceon_integer", osquery::INTEGER_TYPE, osquery::ColumnOptions::DEFAULT),
    };
  }

  ///////////////////////////////
  /* Firewall Quaranting Begin */

  void FirewallQuarantine() 
  {
    std::string output, command, edr_allow, server_string;
    //output = exec_s("iptables-save > /tmp/rules_backup.fw"); 
    exec("iptables-save > /tmp/rules_backup.fw"); //  Saves Rules to /tmp/rules_backup.fw 
    bool filecheck;
    filecheck = FileExists( "/tmp/rules_backup.fw");
    if(filecheck) {
    printf("### Firewall Backup Created Successfully ###\n");
        }
    else
    printf("!!! Firewall Backup Failed !!!");


    
    std::string edr_ip, edr_port;
    getEDRServer(edr_ip,edr_port);
    if (edr_ip.empty() || edr_port.empty())
        {
          printf("EDRServer IP and Port not found. Unable to quarantine!");
          
        }
  exec("iptables --flush");   // Flush All rules 
  exec("iptables --delete-chain"); // Delete all chains
  exec("iptables -A INPUT -i lo -j ACCEPT"); // Allow Loopback ? 
  exec("iptables -A OUTPUT -o lo -j ACCEPT");
  exec("iptables -A OUTPUT -p udp --dport 53 -j ACCEPT"); // Allow DNS lookup
  exec("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"); // Allow Established connections

  /////// Add host to iptables //////// ****** ALLOW all interfaces - change **** 
  edr_allow = "iptables -A INPUT -s " + edr_ip + " -p tcp --dport " + edr_port + " -j ACCEPT"; // Allows connections from source edr_ip on on port edr_port
  printf("%s \n", edr_allow.c_str());
  exec(edr_allow);
  // iptables -A OUTPUT -d 96.237.103.37 -p tcp --dport 443 -o eth0 -j ACCEPT
  // iptables -A INPUT -s demo.seceon.com -p tcp --dport 443 -i eth0 -j ACCEPT  

  edr_allow = "iptables -A OUTPUT -d " + edr_ip + " -p tcp --dport " + edr_port + " -j ACCEPT"; // Allows outgoing connections to destination edr_ip on port edr_port
  // iptables -A OUTPUT -d demo.seceon.com -p tcp --dport 443 -o eth0 -j ACCEPT 

  printf("%s \n", edr_allow.c_str());
  exec(edr_allow);


  // iptables -A <chain> -i <interface> -p <protocol (tcp/udp) > -s <source> --dport <port no.>  -j <target>

  ///// Drop Everything Else /////

  exec("iptables -A INPUT -j DROP");
  exec("iptables -A OUTPUT -j DROP");

  ///// Saves Rules, so that restart of an agent doesnt revert rules ///// 
  exec("/sbin/iptables-save"); // For Ubuntu
  // RedHat / Centos --> /sbin/iptables-save 
  // or --> /etc/init.d/iptables save


    std::cout << "System has been quarantined!" << std::endl;
  }

  void FirewallQuarantine_Revert() {

  exec("iptables --flush");   // Flush All rules 
  exec("iptables --delete-chain"); // Delete all chains
  exec("iptables-restore < /tmp/rules_backup.fw");
  exec("/sbin/iptables-save");

  std::cout << "System Firewall has  been Reverted, Quarantine Ended" << std::endl;


   }


  void eraseSubStr(std::string& mainStr, const std::string& toErase) {
    // Search for the substring in string
    size_t pos = mainStr.find(toErase);
    if (pos != std::string::npos) {
      // If found then erase it from string
      mainStr.erase(pos, toErase.length());
    }
  }

  void tokenize(std::string const& str, const char delim, std::vector<std::string>& out) {
    // construct a stream from the string
    std::stringstream ss(str);

    std::string s;
    while (std::getline(ss, s, delim)) {
      out.push_back(s);
    }
  }  

  void getEDRServer(std::string& edr_ip, std::string& edr_port) {
    std::string line, edrserver, osquery_flags;
    std::ifstream nameFileout;
    const char delim = ':';
    std::vector<std::string> out;

    edrserver = "--tls_hostname=";
    osquery_flags = "/tmp/osquery.flags";    

    nameFileout.open(osquery_flags);

    bool edr_found = 0;
    while (std::getline(nameFileout, line)) {
      // Find occurence of "tls_edrserver"
      size_t found = line.find(edrserver);
      if (found != std::string::npos) {
        eraseSubStr(line, edrserver);
        tokenize(line, delim, out);

        edr_ip = out[0];
        edr_port = out[1];
        std::cout << "edrserver_ip: " << edr_ip << std::endl << "edrserver_port: " << edr_port << std::endl;
        edr_found = 1;
      }
    }
    if(edr_found == false)
    {
      std::cout << "Error: EDRServer_IP and EDRServer_Port not found";
    }
  
  nameFileout.close();  
  }

  std::string exec_s(std::string string) {  // Executes commands and returns the result as std::string
    const char * cmd;
    cmd = string.c_str();
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
      }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
                    }
    return result;
  }
  
void exec(std::string string) { // Executes System Command Only
  const char * cmd;
  cmd = string.c_str();
  std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
      }
}



bool FileExists( const std::string &Filename ) { // Checks if a file exists or not, (Works for both windows and posix)
    return access( Filename.c_str(), 0 ) == 0;
}



  /* Firewall Quaranting End */
  ///////////////////////////////
  //using testrows = vector<osquery::TableRowHolder>;
  //osquery::testrows SeceonTable::generate(osquery::QueryContext& context) override {

  osquery::TableRows generate(osquery::QueryContext& context) override {
    osquery::TableRows results;

    std::cout << "Generate command called!";
    
    // osquery::QueryData QD_results;
    // for (const auto& pkey_row_pair : data) {
    //  QD_results.push_back(pkey_row_pair.second);
    // }

    // results = osquery::tableRowsFromQueryData(std::move(QD_results));
    auto r = osquery::make_table_row();

    r["firewall"] = "test_value";    
    results.emplace_back(r);
    return results;
  }

  /// Callback for INSERT queries
  osquery::QueryData insert(osquery::QueryContext& context, const osquery::PluginRequest& request) override {
    std::lock_guard<std::mutex> lock(mutex);

    std::cout << "\nInsert Command called!\n";
    // Calling Firewall Quarantine
    FirewallQuarantine();

 
    osquery::Row result;
    result["id"] = "10";
    result["status"] = "success";
    return {result};
    
  }

  /// Callback for DELETE queries
  osquery::QueryData delete_(osquery::QueryContext& context, const osquery::PluginRequest& request) override {
    std::lock_guard<std::mutex> lock(mutex);

    std::cout << "\nDelete query start\n";

    // Revert Firewall Quaranting
    FirewallQuarantine_Revert();

    
    return {{std::make_pair("status", "success")}};    
  }
};

// Note 3: Use REGISTER_EXTERNAL to define your plugin or table.
// REGISTER_EXTERNAL(CLASSNAME, "table", "table_name")
REGISTER_EXTERNAL(SeceonTable, "table", "seceon_quarantine");

int main(int argc, char* argv[]) {
  // Note 4: Start logging, threads, etc.
  osquery::Initializer runner(argc, argv, osquery::ToolType::EXTENSION);

  // Note 5: Connect to osqueryi or osqueryd.
  auto status = osquery::startExtension("seceon-extension", "1.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  // Finally, shutdown.
  runner.waitForShutdown();
  return 0;
}
