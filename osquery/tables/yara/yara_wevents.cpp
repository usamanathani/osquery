#include <map>
#include <string>

#include <osquery/config/config.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/tables/yara/yara_utils.h>

#include <osquery/events/windows/ntfs_event_publisher.h>
#include "G:\\osquery\\osquery\\tables\\events\\windows\\ntfs_journal_events.h" // include ntfs_journal_events;




#ifdef CONCAT
#undef CONCAT
#endif
#include <yara.h>

namespace osquery {
using FileEventSubscriber = NTFSEventSubscriber; // inherits from ntfs_journal_events (ntfseventsubscriber class changed from final to public to inherit)
using FileEventContextRef = NTFSEventContextRef;
using FileSubscriptionContextRef = NTFSEventSubscriptionContextRef;

class YARAEventSubscriber : public FileEventSubscriber {
 public:
  Status init() override {
    return Status(0);
  }

  void configure() override;

 private:
  /**
   * @brief This exports a single Callback for FSEventsEventPublisher events.
   *
   * @param ec The Callback type receives an EventContextRef substruct
   * for the FSEventsEventPublisher declared in this EventSubscriber subclass.
   *
   * @return Status
   */
  Status Callback(const FileEventContextRef& ec,
                  const FileSubscriptionContextRef& sc);

};




REGISTER(YARAEventSubscriber, "event_subscriber", "yara_events");

void YARAEventSubscriber::configure() {
  removeSubscriptions();

  // There is a special yara parser that tracks the related top-level keys.
  auto plugin = Config::getParser("yara");
  if (plugin == nullptr || plugin.get() == nullptr) {
    return;
  }

  // Bail if there is no configured set of opt-in paths for yara.
  const auto& yara_config = plugin->getData().doc();
  if (!yara_config.HasMember("file_paths") ||
      !yara_config["file_paths"].IsObject()) {
    return;
  }

  // Collect the set of paths, we are mostly concerned with the categories.
  // But the subscriber must duplicate the set of subscriptions such that the
  // publisher's 'fire'-matching logic routes related events to our callback.
  std::map<std::string, std::vector<std::string>> file_map;
  Config::get().files([&file_map](const std::string& category,
                                  const std::vector<std::string>& files) {
    file_map[category] = files;
  });

  // For each category within yara's file_paths, add a subscription to the
  // corresponding set of paths.
  const auto& yara_paths = yara_config["file_paths"];
  for (const auto& yara_path_element : yara_paths.GetObject()) {
    std::string category = yara_path_element.name.GetString();
    // Subscribe to each file for the given key (category).
    if (file_map.count(category) == 0) {
      VLOG(1) << "Key in YARA file_paths not found in file_paths: " << category;
      continue;
    }

      StringList include_path_list = {}; // path lists for process configuration function in ntfs_journal_events
      StringList exclude_path_list = {};
      StringList access_categories;

    for (const auto& file : file_map.at(category)) {
      VLOG(1) << "Added YARA listener to: " << file;
      auto sc = createSubscriptionContext();
      resolveFilePattern(file, include_path_list); // globbing function that resolves wildcards and expands paths;
      access_categories.push_back(category); // pushes category and file to include paths; 
      include_path_list.push_back(file);           
      //sc->access_paths.insert(file);
      //sc->write_paths.insert(file);
      //const auto& write_paths = sc->write_paths;
      //const auto& access_paths = sc->access_paths;
      //const auto& write_frns = sc->write_frns;
      //const auto& access_frns = sc->access_frns;
      sc->category = category;
     processConfiguration(
            sc, access_categories, include_path_list, exclude_path_list); // processes the configuration and also finds corresponding frns for paths
      
      subscribe(&YARAEventSubscriber::Callback, sc);
    }
  }
}

Status YARAEventSubscriber::Callback(const FileEventContextRef& ec,
                                     const FileSubscriptionContextRef& sc) {

 std::vector<NTFSEventRecord> eventr; 
 
 //eventr = ec -> event_list;

 for (const auto & ex : ec->event_list) { // to resolve the vector 
 //for( auto & ex : eventr) {

 
 //for (auto i = 0; i < eventr.size(); ++i){
  //for(int i=0; i<elen; i++){
  //for(const auto& event : ec->event_list) { 
    
    std::string usnstring;
    USNJournalEventRecord::Type utype;
    utype = ex.type;
    usnstring = kNTFSEventToStringMap.at(utype); // map function that determines type of action

    if(isWriteOperation(ex.type)) { // isWriteoperation is a function part of ntfs_journal_events to determine if a particular action writes or not. 
      return Status(1, "Invalid action");

    }

/*
  if (usnstring != "FileOverwrite" && usnstring != "FileCreation") {
    return Status(1, "Invalid action");
  }
*/

   Row r;
   
  r["action"] = usnstring;
  r["target_path"] = ex.path;
  r["category"] = sc->category;

  // These are default values, to be updated in YARACallback.
  r["count"] = INTEGER(0);
  r["matches"] = std::string("");
  r["strings"] = std::string("");
  r["tags"] = std::string("");

  auto parser = Config::getParser("yara");
  if (parser == nullptr || parser.get() == nullptr) {
    return Status(1, "ConfigParser unknown.");
  }

  std::shared_ptr<YARAConfigParserPlugin> yaraParser;
  try {
    yaraParser = std::dynamic_pointer_cast<YARAConfigParserPlugin>(parser);
  } catch (const std::bad_cast& e) {
    return Status(1, "Error casting yara config parser plugin");
  }
  if (yaraParser == nullptr || yaraParser.get() == nullptr) {
    return Status(1, "Yara parser unknown.");
  }

  auto rules = yaraParser->rules();

  // Use the category as a lookup into the yara file_paths. The value will be
  // a list of signature groups to scan with.
  auto category = r.at("category");
  const auto& yara_config = parser->getData().doc();
  const auto& yara_paths = yara_config["file_paths"];
  const auto group_iter = yara_paths.FindMember(category);
  if (group_iter != yara_paths.MemberEnd()) {
    for (const auto& rule : group_iter->value.GetArray()) {
      std::string group = rule.GetString();
      int result = yr_rules_scan_file(rules[group],
                                      ex.path.c_str(),
                                      SCAN_FLAGS_FAST_MODE,
                                      YARACallback,
                                      (void*)&r,
                                      0);

      if (result != ERROR_SUCCESS) {
        return Status(1, "YARA error: " + std::to_string(result));
      }
    }
  }

  if (usnstring != "" && !r.at("matches").empty()) {
    add(r);
  }

  return Status::success();
  }
}

/* void processConfiguration(const FileSubscriptionContextRef context,
                          const StringList& access_categories,
                          StringList& include_paths,
                          StringList& exclude_paths); */

} // namespace  - osquery
