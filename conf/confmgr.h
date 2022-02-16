#include <stddef.h>
#include <stdint.h>
#include <string>
#include <set>
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

class lockguard {
  public:
    lockguard(spinlock &lock) : lock_(lock)
    {
        lock_.lock();
    }

    ~lockguard()
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
        lockguard guard(workspace_lock);

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
            std::set<Key> keys = {key};
            if (int err = pull(relevant_keys(key, keys)); err != 0) {
                return err;
            }
        }

        {
            lockguard guard(workspace_lock);
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
        {
            lockguard guard(push_stage_lock);
            push_stage[key] = value;
        }

        if (try_push) {
            std::set<Key> keys = {key};
            return push(relevant_keys(key, keys));
        }

        return 0;
    }

    virtual int push(const std::set<Key> &keys)
    {
        lockguard guard_stage(push_stage_lock);

        /* push to storage */
        {
            if (int err = sync_push(keys, push_stage); err != 0) {
                return err;
            }
        }

        /* swap with stage */
        {
            lockguard guard(workspace_lcok);
            for (auto &key : keys) {
                if (push_stage.count(key)) {
                    workspace[key] = push_stage[key];
                    push_stage.erase(key);
                }
            }
        }

        return 0;
    }

    virtual int pull(const std::set<Key> &keys)
    {
        lockguard guard_stage(pull_stage_lock);

        /* pull from storage */
        {
            if (int err = sync_pull(keys, pull_stage); err != 0) {
                return err;
            }
        }

        /* swap with stage */
        {
            lockguard guard(workspace_lcok);
            for (auto &key : keys) {
                if (pull_stage.count(key)) {
                    workspace[key] = pull_stage[key];
                    pull_stage.erase(key);
                }
            }
        }

        return 0;
    }

  protected:
    virtual std::set<Key> &relevant_keys(const Key &, std::set<Key> &keys)
    {
        return keys;
    }

    virtual int sync_pull(const std::set<Key> &, std::unordered_map<Key, std::variant<Values...>> &)
    {
        return 0;
    }

    virtual int sync_push(const std::set<Key> &, const std::unordered_map<Key, std::variant<Values...>> &)
    {
        return 0;
    }

    spinlock workspace_lock, pull_stage_lock, push_stage_lock;
    std::unordered_map<Key, std::variant<Values...>> workspace;
    std::unordered_map<Key, std::variant<Values...>> pull_stage;
    std::unordered_map<Key, std::variant<Values...>> push_stage;
};

template <typename Key = std::string>
class DistributedManager : public Manager<Key, bool, uint32_t, uint64_t, std::string> {
  public:
    DistributedManager(std::string repo, std::string branch)
        : repo_(std::move(repo)), branch_(std::move(branch))
    {
    }

  protected:
    virtual int sync_pull(const std::set<Key> &,
                          std::unordered_map<Key, std::variant<Values...>> &) override
    {
        return 0;
    }

    virtual int sync_push(const std::set<Key> &,
                          const std::unordered_map<Key, std::variant<Values...>> &) override
    {
        return 0;
    }

  private:
    std::string repo_;
    std::string branch_;
};

template <typename Key = std::string>
class FileManager : public Manager<Key, bool, uint32_t, uint64_t, std::string> {
  public:
    FileManager(std::string path) : path_(std::move(path)) {}

  protected:
    virtual int sync_pull(const std::set<Key> &,
                          std::unordered_map<Key, std::variant<Values...>> &) override
    {
        return 0;
    }

    virtual int sync_push(const std::set<Key> &,
                          const std::unordered_map<Key, std::variant<Values...>> &) override
    {
        return 0;
    }

  private:
    std::string path_;
};
} // namespace conf
