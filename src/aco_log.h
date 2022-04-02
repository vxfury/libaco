#include <string>
#include <vector>
#include <memory>
#include <stdarg.h>
#include <functional>

namespace aco
{
namespace logging
{
struct detail {
    int id;
    int level;
    struct timeval tv;
    std::string content;
    const char *location;

    std::string time() const;

    detail(int id, const char *location, int level, const char *fmt, va_list ap);
};
using printer_type = std::function<void(int id, const std::string &uuid, const std::vector<detail> &details,
                                        const std::vector<std::string> &stages)>;

class cached_logger {
  public:
    cached_logger();
    cached_logger(const char *fmt, ...);
    ~cached_logger();

    void clear();
    void flush();
    void reset(const char *fmt, ...);
    void add_printer(printer_type printer);

    void add_stage(const char *fmt, ...);
    void add_detail(const char *location, int level, const char *fmt, ...);

    template <typename Logger>
    class cleaner {
      public:
        cleaner(Logger &logger) : drop(false), offset(logger.details.size()), logger(logger) {}

        ~cleaner()
        {
            if (drop) {
                auto &details = logger.details;
                details.erase(details.begin() + offset, details.end());
            }
        }

        size_t size() const
        {
            return logger.details.size() - offset;
        }

        void discard(bool drop_or_not = true)
        {
            drop = drop_or_not;
        }

      private:
        bool drop;
        size_t offset;
        Logger &logger;
    };

    std::shared_ptr<cleaner<cached_logger>> make_cleaner()
    {
        return std::make_shared<cleaner<cached_logger>>(*this);
    }

  private:
    int id;
    std::string uuid;
    std::vector<detail> details;
    std::vector<std::string> stages;
    std::vector<printer_type> printers;
};
} // namespace logging

#define TOSTRING(line)       #line
#define TAIL_OFFSET(path)    (__builtin_strrchr(path, '/') ? (__builtin_strrchr(path, '/') - path + 1) : 0)
#define LOCATION(file, line) &file ":" TOSTRING(line)[TAIL_OFFSET(file)]
} // namespace aco
