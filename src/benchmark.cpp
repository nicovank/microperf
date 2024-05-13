#include <chrono>
#include <iostream>

int main() {
    using Clock = std::chrono::high_resolution_clock;
    auto start = Clock::now();
    std::uint64_t sum = 0;
    while (std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - start).count() < 5) {
        sum += 1;
    }
    std::cout << "Work done! " << sum << std::endl;
}
