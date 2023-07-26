#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace uperf::maps {
struct Map {
    std::uint64_t addr;
    std::uint64_t len;
    std::uint64_t pgoff;
    std::string filename;
};

class Maps {
  public:
    void addMap(std::uint64_t addr, std::uint64_t len, std::uint64_t pgoff, std::string filename);
    void removeMap(std::uint64_t addr, std::uint64_t len);
    std::optional<std::pair<std::string, std::uint64_t>> resolve(std::uint64_t addr) const;
    const std::vector<Map>& getMaps() const;

  private:
    std::vector<Map> maps;
};
} // namespace uperf::maps
