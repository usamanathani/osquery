// Note 1: Include the sdk.h helper.
/* // << For updated OSQUERY USE >> 
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/logger/logger.h> */

#include <osquery/system.h> //<< OLD OSQUERY USE >> 
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
  std::string firewall_backup = "/etc/osquery/rules_backup.fw";
  std::string firewall_default = "/etc/osquery/rules_default.fw";
  std::string firewall_save = "iptables-save > " + firewall_default;
  std::string osquery_dir = "/etc/osquery/";
  //std::string netsh_location = "C:\\Windows\\System32\\netsh.exe";
  //std::string osquery_path = "\"%ProgramFiles%\\osquery\\osqueryd\\osqueryd.exe\""; 
  
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
  exec("iptables-save > /etc/osquery/rules_backup.fw"); //  Saves Rules to /etc/osquery/rules_backup.fw"
  bool filecheck;
  filecheck = FileExists( "/etc/osquery/rules_backup.fw");
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

  std::string ip_flush, ip_del, ip_loop1, ip_loop2, ip_dns, ip_est, ip_edr1, ip_edr2, ip_drop, ip_save, ip_buffer;
  ip_flush = "iptables --flush"; // Flush All rules 
  exec(ip_flush);
  ip_del = "iptables --delete-chain"; // Delete all chains
  exec(ip_del);
  ip_loop1 = "iptables -A INPUT -i lo -j ACCEPT"; // Allow Loopback
  exec(ip_loop1);
  ip_loop2 = "iptables -A OUTPUT -o lo -j ACCEPT";
  exec(ip_loop2);
  ip_dns = "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT"; // Allow DNS lookup
  exec(ip_dns);
  ip_est = "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"; // Allow Established connections
  exec(ip_est);
  /////// Add host to iptables ////////
  ip_edr1 = "iptables -A INPUT -s " + edr_ip + " -p tcp --dport " + edr_port + " -i eth0 -j ACCEPT"; // Allows connections from source edr_ip on on port edr_port
  exec(ip_edr1);
  ip_edr2 = "iptables -A OUTPUT -d " + edr_ip + " -p tcp --dport " + edr_port + " -o eth0 -j ACCEPT"; // Allows outgoing connections to destination edr_ip on port edr_port
  exec(ip_edr2);
  ip_drop = "iptables -A INPUT -j DROP"; // Drop Everything Else
  exec(ip_drop); 
  ip_save = "iptables-save > /etc/osquery/rules_default.fw";
  exec(ip_save);

  // Allow SSH connections /// 
  /*exec("iptables -A INPUT -p tcp --dport 22 -j ACCEPT");
  exec("iptables -A INPUT -p tcp --dport 80 -j ACCEPT");
  */


/*
  /// Allow SSH connections from host, but not to. (If SSH connection is made from host to agent, data can be exchanged however, agent to host ssh connection cannot be made, 
  //host must initiate)
  edr_allow = "iptables -A INPUT -p tcp --dport ssh -s " + edr_ip + " -m state --state NEW,ESTABLISHED -j ACCEPT";
  exec(edr_allow);
  edr_allow = "iptables -A OUTPUT -p tcp --sport 22 -d " + edr_ip + " -m state --state ESTABLISHED -j ACCEPT";
  exec(edr_allow);
*/


  /*output = exec_s("host "+ edr_ip);
  printf("%s",output.c_str()); // demo.seceon.com has address 96.237.103.37
  server_string = edr_ip + " has address ";
  eraseSubStr(output, server_string);
  printf("%s", output.c_str()); */
/*
  /////// Add host to iptables ////////
  edr_allow = "iptables -A INPUT -s " + edr_ip + " -p tcp --dport " + edr_port + " -i eth0 -j ACCEPT"; // Allows connections from source edr_ip on on port edr_port
  printf("%s \n", edr_allow.c_str());
  exec(edr_allow);
  // iptables -A OUTPUT -d 96.237.103.37 -p tcp --dport 443 -o eth0 -j ACCEPT 

  edr_allow = "iptables -A OUTPUT -d " + edr_ip + " -p tcp --dport " + edr_port + " -o eth0 -j ACCEPT"; // Allows outgoing connections to destination edr_ip on port edr_port
  // iptables -A OUTPUT -d demo.seceon.com -p tcp --dport 443 -o eth0 -j ACCEPT
  // iptables -A <chain> -i <interface> -p <protocol (tcp/udp) > -s <source> --dport <port no.>  -j <target>
  printf("%s \n", edr_allow.c_str());
  exec(edr_allow);

  ///// Drop Everything Else /////

  exec("iptables -A INPUT -j DROP");
  exec("iptables-save > /etc/osquery/rules_default.fw");

  ///// Saves Rules, so that restart of an agent doesnt revert rules ///// 
  exec("/sbin/iptables-save"); // For Ubuntu
  // RedHat / Centos --> /sbin/iptables-save 
  // or --> /etc/init.d/iptables save
*/

  bool iptables_script, script_flag; // Creating Script to Restore Default Rules
  iptables_script = FileExists("/etc/osquery/iptables_save.sh");
  if(!iptables_script){ // IPTRABLE SCRIPT START
    std::fstream script;
    exec("touch /etc/osquery/iptables_save.sh");
    exec("chmod 777 /etc/osquery/iptables_save.sh");
    script.open("/etc/osquery/iptables_save.sh");
    if(script.is_open()) {

      printf("Script Opened\n");
      script << "#!/bin/bash\n\n";
      script << "iptables-restore < /etc/osquery/rules_default.fw";
      script.close();
      exec("chmod 744 /etc/osquery/iptables_save.sh");
      script_flag = true;

    }
    else{
      printf("Script Did Not Open\n");
      script_flag = false;
    }
      
  } // IPTABLES SCRIPT END
  else
    script_flag = true;


  bool service_exists, service_flag; // Creating Service to Run Script on Reboot
  service_exists = FileExists("/etc/systemd/system/iptables_rules_save.service");
  if(!service_exists) { // SERVICE EXISTS START
    std::fstream file;
    exec("touch /etc/systemd/system/iptables_rules_save.service");
    exec("chmod 777 /etc/systemd/system/iptables_rules_save.service");
    file.open("/etc/systemd/system/iptables_rules_save.service");
    if(file.is_open()) {
      printf("File Opened \n");
      file << "[Unit]\nDescription=Iptables-Save-Reboot\n\n";
      file << "[Service]\nType=simple\n";
      file << "Restart=on-failure\n";
      file << "RestartSec=1\n";
      file << "ExecStart=/bin/bash /etc/osquery/iptables_save.sh\n\n";
      file << "[Install]\n";
      file << "WantedBy=multi-user.target";
      file.close();
      service_flag = true;
      exec("chmod 664 /etc/systemd/system/iptables_rules_save.service"); // Setting permissions is important or service wont work*
                        }
    else{
      printf("File could not be opened\n");
      service_flag = false;
    }
      
    

    } // SERVICE EXISTS END
    else
      service_flag = true;

    if(script_flag && service_flag) { // Enabling and Starting Service
      
      exec("systemctl enable iptables_rules_save");
      exec("systemctl start iptables_rules_save");
      exec("systemctl daemon-reload");
      printf("Service has Started and been Enabled\n");
    }

/*PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
export DISPLAY=:0.0
*/ 
// Adding a script that shall be run every 30 minutes to ensure EDR connection always resolves while system is in quarantine // 
  bool edr_script, edrscript_flag; 
  edr_script = FileExists("/etc/osquery/edr_connect30.sh");
  if(!edr_script) { // EDR SCRIPT START
    std::fstream script;
    exec("touch /etc/osquery/edr_connect30.sh");
    exec("chmod 700 /etc/osquery/edr_connect30.sh");
    script.open("/etc/osquery/edr_connect30.sh");
    if(script.is_open()) {
      printf("EDR Connect 30 Minutes Script Opened\n");
      script << "#!/bin/bash\n\n";
      script <<"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\nexport DISPLAY=:0.0\n"; // Giving Path is essential << 
      ip_buffer = ip_flush + "\n" + ip_del + "\n" + ip_loop1 + "\n" + ip_loop2 + "\n"; // Using same commands used above to resolve and add host. 
      script << ip_buffer;
      ip_buffer = ip_dns + "\n" + ip_est + "\n" + ip_edr1 + "\n" + ip_edr2 + "\n" + ip_drop + "\n" + ip_save + "\n";
      script << ip_buffer;
      script.close();
      printf("EDR Connect 30 Minutes Script Created! \n");
      edrscript_flag = true;
      exec("chmod +x /etc/osquery/edr_connect30.sh");
      }
    else {
      printf("EDR Connect 30 Script Failed to Open! \n");
      edrscript_flag = false;
       }
   } // EDR SCRIPT END
  else 
    edrscript_flag=true;


/// APPEND TO CRONTAB ; */30 * * * * /etc/osquery/edr_connect30.sh 
 // */30  --> every 30 minutes (divisible by 30), can set it to */10 for the script to run every 10 minutes << 
  /// sudo systemctl start crond.service     (Centos7) ?
    bool cron_edrscript;
    cron_edrscript = FileExists("/etc/cron.d/edr_c30");
    if(!cron_edrscript && edrscript_flag) { // CRON START
      exec("touch /etc/cron.d/edr_c30"); // Name of the file cannot contain extensions or it will be ignored.)
      exec("chmod 777 /etc/cron.d/edr_c30");
      std::fstream file;
      file.open("//etc/cron.d/edr_c30");
      if(file.is_open()) {
        file <<"SHELL=/bin/sh\n";
        file <<"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n";
        file <<"*/30 * * * * root /etc/osquery/edr_connect30.sh\n"; // cron.d files should have a line break at the end of the file to ensure it works
        file.close();
        exec("chown -R root:root /etc/cron.d/edr_c30"); // Make sure cron.d is owned by root (MUST BE OWNED BY ROOT for cron.d)
        exec("chmod 644 /etc/cron.d/edr_c30"); // chmod 644 to allow for Centos, 700 works on ubuntu, not on Centos 7
        exec("systemctl restart cron >/dev/null 2>&1"); // Restart Cron Service
        exec("systemctl restart crond >/dev/null 2>&1"); // Restart Cron Service for Centos (>/dev/null 2>&1     , (one of them will always show error output depending on system, since 
        printf("CRON D Edr Script Created!\n"); //                                                                 centos 7 requires crond restart instead of cron )
      }
      else
        printf("CronD EDR Script could not be opened!\n");        
    } // CRON END
  

    std::cout << "System has been quarantined!" << std::endl;
    
 } // FIREWALL QUARANTINE END

  void FirewallQuarantine_Revert() {
  std::string buffer;
  exec("iptables --flush");   // Flush All rules 
  exec("iptables --delete-chain"); // Delete all chains
  buffer = "iptables-restore < " + firewall_backup;
  exec(buffer);
  exec(firewall_save);
  printf("FireBackup Restored!\n");
  exec("rm /etc/osquery/iptables_save.sh"); // Removes Ip-tables save on reboot script
  exec("rm /etc/systemd/system/iptables_rules_save.service"); // Removes Ip-tables service reboot Script
  printf("Ip Tables Reboot-Save Script and Service Removed\n");
  exec("rm /etc/osquery/edr_connect30.sh"); // Remove Script to flush and re-add host
  exec("rm /etc/cron.d/edr_c30"); // Remove cron.d job to run script every 30 min
  printf("Re-add Script and Cron.d Job Removed!\n");
  

  std::cout << "System Firewall has  been Reverted, Quarantine Ended" << std::endl;


   } // FIREWALL REVERT END <<<


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
    osquery_flags = osquery_dir + "osquery.flags";  

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
