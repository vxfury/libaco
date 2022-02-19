#include <vector>
#include <iostream>
#include "confmgr.h"

struct hashfun {
    template <typename T>
    size_t operator()(const std::vector<T> &vec) const
    {
        size_t h = 0;
        for (auto v : vec) {
            h ^= std::hash<T>()(v);
        }
        return h;
    }
};

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
        std::unordered_map<std::vector<int>, std::vector<std::string>, hashfun> val7 = {
            {{1, 2, 3}, {"key1", "key2", "key3"}},
            {{4, 5, 6}, {"key1", "key3", "key5"}},
            {{3, 5}, {"key9", "key0"}},
        };

        mgr.set<std::string>("key4", val4);
        mgr.set<std::string>("key5", val5);
        mgr.set<std::string>("key6", val6);
        mgr.set<std::string>("key7", val7);

        std::cout << "key4: " << mgr.get_as<std::string>("key4", "") << std::endl;
        std::cout << "key5: " << mgr.get_as<std::string>("key5", "") << std::endl;
        std::cout << "key6: " << mgr.get_as<std::string>("key6", "") << std::endl;
        std::cout << "key7: " << mgr.get_as<std::string>("key7", "") << std::endl;

        std::cout << std::endl;
        {
            std::cout << "key4: [";
            for (auto v : mgr.get_as<std::vector<int>, std::string>("key4", {})) {
                std::cout << v << ", ";
            }
            std::cout << "]" << std::endl;
        }

        {
            std::cout << "key5: [";
            for (auto vec : mgr.get_as<std::vector<std::vector<int>>, std::string>("key5", {})) {
                std::cout << "[";
                for (auto v : vec) {
                    std::cout << v << ", ";
                }
                std::cout << "], ";
            }
            std::cout << "]" << std::endl;
        }

        {
            std::cout << "key6: [";
            for (auto mm :
                 mgr.get_as<std::unordered_map<std::string, std::vector<int>>, std::string>("key6", {})) {
                std::cout << mm.first << ": [";
                for (auto v : mm.second) {
                    std::cout << v << ", ";
                }
                std::cout << "]; ";
            }
            std::cout << std::endl;
        }

        {
            std::cout << "key7: [";
            for (auto mm :
                 mgr.get_as<std::unordered_map<std::vector<int>, std::vector<std::string>, hashfun>,
                            std::string>("key7", {})) {
                std::cout << "[";
                for (auto v : mm.first) {
                    std::cout << v << ", ";
                }
                std::cout << "]: [";
                for (auto v : mm.second) {
                    std::cout << v << ", ";
                }
                std::cout << "]; ";
            }
            std::cout << std::endl;
        }
    }

    return 0;
}
