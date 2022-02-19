#include <vector>
#include <iostream>
#include "confmgr.h"

int main()
{
    conf::DistributedManager mgr("repo", "master");

    // native types
    {
        bool val1 = true;
        int val2 = 100;
        std::string val3 = "string";

        mgr.set("key1", val1);
        mgr.set("key2", val2);
        mgr.set("key3", val3);

        if (mgr.has("key1")) {
            std::cout << "has: key1" << std::endl;
        }
        std::cout << "key1: " << mgr.get_as<bool>("key1", false) << std::endl;
        std::cout << "key2: " << mgr.get_as<int>("key2", 0) << std::endl;
    }

    // containers
    {
        std::vector<int> val4{1, 2, 4, 8, 16};
        std::vector<std::vector<int>> val5 = {{1, 2, 3}, {4, 5, 6}, {8, 0, 10, 12}};
        std::unordered_map<std::string, std::vector<int>> val6 = {
            {"key1", {1, 2, 3}},
            {"key2", {4, 5, 6}},
            {"key3", {8, 0, 10, 12}},
        };

        mgr.set<std::vector<int>, std::string>("key4", val4);
        mgr.set<std::vector<std::vector<int>>, std::string>("key5", val5);
        mgr.set<std::unordered_map<std::string, std::vector<int>>, std::string>("key6", val6);

        std::cout << "key4: " << mgr.get_as<std::string>("key4", "") << std::endl;
        std::cout << "key4: ";
        for (auto v : mgr.get_as<std::vector<int>, std::string>("key4", {})) {
            std::cout << v << ", ";
        }
        std::cout << std::endl;
    }

    return 0;
}
