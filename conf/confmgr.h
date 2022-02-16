#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <variant>
#include <atomic>
#include <type_traits>
#include <unordered_map>

namespace conf
{
class spinlock {
  public:
    spinlock() = default;
    spinlock(const spinlock &) = delete;
    spinlock &operator=(const spinlock &) = delete;

    void lock()
    {
        bool expected = false;
        while (!flag.compare_exchange_strong(expected, true)) {
            expected = false;
        }
    }

    void unlock()
    {
        flag.store(false);
    }

  private:
    std::atomic<bool> flag = ATOMIC_VAR_INIT(false);
};

class lock_guard {
  public:
    lock_guard(spinlock &lock) : lock_(lock)
    {
        lock_.lock();
    }

    ~lock_guard()
    {
        lock_.unlock();
    }

  private:
    spinlock &lock_;
};

template <typename Key, typename... Values>
class Manager {
  public:
    template <typename T = void>
    bool has(const Key &key)
    {
        lock_guard guard(workspace_lock);

        if constexpr (std::is_same_v<T, void>) {
            return workspace.count(key) != 0;
        } else {
            if (workspace.count(key)) {
                if (std::get_if<T>(workspace.at(key)) != nullptr) {
                    return true;
                }
            }
            return false;
        }
    }

    template <typename T>
    int get(const Key &key, T &value, bool try_pull)
    {
        if (try_pull) {
            auto keys = relevant_keys(key);
            if (keys.size() > 0) {
                if (int err = pull(keys); err != 0) {
                    return err;
                }
            } else {
                if (int err = pull(key); err != 0) {
                    return err;
                }
            }
        }
        if (workspace.count(key) > 0) {
            if (const T *p = std::get_if<T>(&workspace.at(key)); p != nullptr) {
                value = *p;
                return 0;
            } else {
                return -EINVAL;
            }
        }
        return -ENOENT;
    }

    template <typename T>
    T get(const Key &key, const T &defval, bool try_pull = true)
    {
        T val;
        if (get(key, val, try_pull) != 0) {
            val = defval;
        }
        return val;
    }

    template <typename T>
    int set(const Key &key, const T &value, bool try_push = true)
    {
        push_stage[key] = value;
        if (try_push) {
            auto keys = relevant_keys(key);
            if (keys.size() > 0) {
                return push(keys);
            } else {
                return push(key);
            }
        }

        return 0;
    }

    virtual int push(const Key &key) = 0;
    virtual int pull(const Key &key) = 0;

    virtual int push(const std::vector<Key> &keys) = 0;
    virtual int pull(const std::vector<Key> &keys) = 0;

  protected:
    virtual std::vector<Key> relevant_keys(const Key &)
    {
        return std::vector<Key>();
    }

    spinlock workspace_lock, pull_stage_lock, push_stage_lock;
    std::unordered_map<Key, std::variant<Values...>> workspace;
    std::unordered_map<Key, std::variant<Values...>> pull_stage;
    std::unordered_map<Key, std::variant<Values...>> push_stage;
};

class DistributedManager : public Manager<std::string, bool, uint32_t, uint64_t, std::string> {
  public:
    DistributedManager(std::string repo, std::string branch)
        : repo_(std::move(repo)), branch_(std::move(branch))
    {
    }

  protected:
    virtual int push(const std::string &name) override
    {
        /* push to remote */

        /* swap with stage */
        {
            workspace[name] = push_stage[name];
            push_stage.erase(name);
        }

        return 0;
    }

    virtual int pull(const std::string &name) override
    {
        /* pull from remote */

        return 0;
    }

    virtual int push(const std::vector<std::string> &names) override
    {
        /* push to remote */

        /* swap with stage */
        for (auto &name : names) {
            workspace[name] = push_stage[name];
            push_stage.erase(name);
        }

        return 0;
    }

    virtual int pull(const std::vector<std::string> &names) override
    {
        /* pull from remote */

        return 0;
    }

  private:
    std::string repo_;
    std::string branch_;
};

class FileManager : public Manager<std::string, bool, uint32_t, uint64_t, std::string> {
  public:
    FileManager(std::string path) : path_(std::move(path)) {}

  protected:
    virtual int push(const std::string &name) override
    {
        /* push to file */

        /* swap with stage */
        {
            workspace[name] = push_stage[name];
            push_stage.erase(name);
        }

        return 0;
    }

    virtual int pull(const std::string &name) override
    {
        /* pull from file */

        return 0;
    }

    virtual int push(const std::vector<std::string> &names) override
    {
        /* push to file */

        /* swap with stage */
        for (auto &name : names) {
            workspace[name] = push_stage[name];
            push_stage.erase(name);
        }

        return 0;
    }

    virtual int pull(const std::vector<std::string> &names) override
    {
        /* pull from file */

        return 0;
    }

  private:
    std::string path_;
};
} // namespace conf
