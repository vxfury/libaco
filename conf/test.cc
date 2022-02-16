#include <iostream>
#include "confmgr.h"

int main()
{
    conf::DistributedManager mgr("repo", "master");

    mgr.set("key1", true);
    if (mgr.has("key1")) {
        std::cout << "has: key1" << std::endl;
    }
    std::cout << "key1: " << mgr.get<std::string>("key1", "defval(incorrect type)") << std::endl;
    std::cout << "key2: " << mgr.get<std::string>("key2", "defval(key not exists)") << std::endl;
}
