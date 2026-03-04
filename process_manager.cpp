// NodeWings Process Manager (Linux)
//
// Build:
//   g++ -O2 -std=c++17 process_manager.cpp -o process_manager
//
// Usage:
//   ./process_manager spawn --ram-mb 512 --cpu-pct 100 -- node index.js
//
// The manager starts a child process, monitors CPU and RAM, and kills it
// if limits are exceeded.

#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

struct Limits {
  double ram_mb = 0.0;
  double cpu_pct = 0.0;
};

std::optional<long long> ReadProcessRssKb(pid_t pid) {
  std::ifstream in("/proc/" + std::to_string(pid) + "/status");
  if (!in) return std::nullopt;

  std::string line;
  while (std::getline(in, line)) {
    if (line.rfind("VmRSS:", 0) == 0) {
      std::istringstream iss(line);
      std::string key;
      long long rss_kb = 0;
      std::string unit;
      iss >> key >> rss_kb >> unit;
      return rss_kb;
    }
  }
  return std::nullopt;
}

std::optional<unsigned long long> ReadProcessCpuTicks(pid_t pid) {
  std::ifstream in("/proc/" + std::to_string(pid) + "/stat");
  if (!in) return std::nullopt;

  std::string line;
  std::getline(in, line);
  if (line.empty()) return std::nullopt;

  // /proc/<pid>/stat fields:
  // utime = field 14, stime = field 15
  std::istringstream iss(line);
  std::vector<std::string> fields;
  std::string token;
  while (iss >> token) fields.push_back(token);

  if (fields.size() < 15) return std::nullopt;

  unsigned long long utime = std::strtoull(fields[13].c_str(), nullptr, 10);
  unsigned long long stime = std::strtoull(fields[14].c_str(), nullptr, 10);
  return utime + stime;
}

std::optional<unsigned long long> ReadTotalCpuTicks() {
  std::ifstream in("/proc/stat");
  if (!in) return std::nullopt;

  std::string cpu;
  unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
  in >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;
  if (cpu != "cpu") return std::nullopt;

  return user + nice + system + idle + iowait + irq + softirq + steal;
}

void ApplyChildGuardrails() {
  // Limit number of processes to reduce fork-bomb impact.
  struct rlimit proc_limit;
  proc_limit.rlim_cur = 128;
  proc_limit.rlim_max = 128;
  setrlimit(RLIMIT_NPROC, &proc_limit);
}

int SpawnAndMonitor(const Limits& limits, const std::vector<std::string>& cmd) {
  if (cmd.empty()) {
    std::cerr << "No command provided\n";
    return 1;
  }

  pid_t child = fork();
  if (child < 0) {
    std::cerr << "fork failed\n";
    return 1;
  }

  if (child == 0) {
    ApplyChildGuardrails();

    std::vector<char*> argv;
    argv.reserve(cmd.size() + 1);
    for (const auto& part : cmd) {
      argv.push_back(const_cast<char*>(part.c_str()));
    }
    argv.push_back(nullptr);

    execvp(argv[0], argv.data());
    std::cerr << "execvp failed: " << strerror(errno) << "\n";
    _exit(127);
  }

  std::cout << "spawned pid=" << child << "\n";

  auto prev_proc_ticks = ReadProcessCpuTicks(child).value_or(0);
  auto prev_total_ticks = ReadTotalCpuTicks().value_or(0);

  while (true) {
    int status = 0;
    pid_t result = waitpid(child, &status, WNOHANG);
    if (result == child) {
      if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        std::cout << "child exited code=" << code << "\n";
        return code;
      }
      if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        std::cout << "child killed by signal=" << sig << "\n";
        return 128 + sig;
      }
      return 1;
    }

    if (result < 0) {
      std::cerr << "waitpid failed\n";
      return 1;
    }

    const auto rss_kb_opt = ReadProcessRssKb(child);
    const auto proc_ticks_opt = ReadProcessCpuTicks(child);
    const auto total_ticks_opt = ReadTotalCpuTicks();

    if (!rss_kb_opt || !proc_ticks_opt || !total_ticks_opt) {
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
      continue;
    }

    const double rss_mb = static_cast<double>(*rss_kb_opt) / 1024.0;
    const auto proc_delta = *proc_ticks_opt - prev_proc_ticks;
    const auto total_delta = *total_ticks_opt - prev_total_ticks;

    prev_proc_ticks = *proc_ticks_opt;
    prev_total_ticks = *total_ticks_opt;

    double cpu_pct = 0.0;
    if (total_delta > 0) {
      cpu_pct = (100.0 * static_cast<double>(proc_delta)) /
                static_cast<double>(total_delta);
    }

    if (limits.ram_mb > 0.0 && rss_mb > limits.ram_mb) {
      std::cerr << "RAM limit exceeded: " << rss_mb << "MB > "
                << limits.ram_mb << "MB\n";
      kill(child, SIGKILL);
    }

    if (limits.cpu_pct > 0.0 && cpu_pct > limits.cpu_pct) {
      std::cerr << "CPU limit exceeded: " << cpu_pct << "% > "
                << limits.cpu_pct << "%\n";
      kill(child, SIGKILL);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2 || std::string(argv[1]) != "spawn") {
    std::cerr << "Usage: process_manager spawn [--ram-mb N] [--cpu-pct N] -- cmd...\n";
    return 1;
  }

  Limits limits;
  std::vector<std::string> command;

  bool parse_command = false;
  for (int i = 2; i < argc; ++i) {
    std::string arg = argv[i];

    if (arg == "--") {
      parse_command = true;
      continue;
    }

    if (!parse_command && arg == "--ram-mb" && i + 1 < argc) {
      limits.ram_mb = std::stod(argv[++i]);
      continue;
    }

    if (!parse_command && arg == "--cpu-pct" && i + 1 < argc) {
      limits.cpu_pct = std::stod(argv[++i]);
      continue;
    }

    if (!parse_command) {
      std::cerr << "Unknown argument: " << arg << "\n";
      return 1;
    }

    command.push_back(arg);
  }

  return SpawnAndMonitor(limits, command);
}
