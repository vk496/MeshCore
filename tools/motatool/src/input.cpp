#include "input.h"
#include "util.h"
#include <unistd.h>

namespace mota {

bool is_url(const std::string& s) {
  return s.rfind("http://", 0) == 0 || s.rfind("https://", 0) == 0;
}

std::string read_input(const std::string& src, std::vector<uint8_t>& out) {
  if (!is_url(src)) {
    if (!read_file(src, out)) return "cannot read file: " + src;
    if (out.empty()) return "file is empty: " + src;
    return "";
  }
  // URL: download to a temp file via curl (fallback wget), then read it back.
  char tmp[] = "/tmp/motadlXXXXXX";
  int fd = mkstemp(tmp);
  if (fd < 0) return "mkstemp failed";
  close(fd);
  // curl: -f fail on HTTP error, -L follow redirects, -s silent, -S show errors, -o out
  int rc = run_argv({"curl", "-fLsS", "-o", tmp, src});
  if (rc == 127)                                  // no curl -> try wget
    rc = run_argv({"wget", "-q", "-O", tmp, src});
  std::string err;
  if (rc == 127) err = "neither curl nor wget is available to fetch " + src;
  else if (rc != 0) err = "download failed (exit " + std::to_string(rc) + "): " + src;
  else if (!read_file(tmp, out) || out.empty()) err = "downloaded file is empty: " + src;
  unlink(tmp);
  return err;
}

} // namespace mota
