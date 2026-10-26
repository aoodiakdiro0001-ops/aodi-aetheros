// AetherOS native kernel runner — the SAME IR bytecode, compiled for this
// architecture's CPU (ARM64 here, x86_64 there: one IR, many machines).
//
// This is the honest cross-architecture story: instead of fantasy binary
// rewriting between ISAs, AetherOS ships one portable IR + one runner per
// architecture. ARM and x86 execute identical semantics — verified by
// tests (Python runner vs this runner must print the same scaled integer).
//
// Build:  c++ -O2 -std=c++17 -o aether_vm aether_vm.cpp
// Usage:  ./aether_vm kernel.json 7,3        (inputs = comma list)
//         echo '{"ir":...}' | ./aether_vm --stdin 7,3
//
// Minimal JSON reader for the restricted IR shape only — no general JSON,
// no dependencies. © 2026 Baran Avisat
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

struct Op {
  std::string code;
  bool has_num = false;
  long long num = 0;
  std::string arg;  // LOAD name
};

// ---- tiny recursive-descent reader for IR-JSON (arrays/strings/ints) ---
struct Json {
  enum { ARR, STR, NUM } kind = ARR;
  std::vector<Json> arr;
  std::string str;
  long long num = 0;
};

struct Parser {
  const std::string &s;
  size_t i = 0;
  explicit Parser(const std::string &src) : s(src) {}

  void ws() { while (i < s.size() && isspace((unsigned char)s[i])) i++; }

  Json parse() {
    ws();
    if (i >= s.size()) throw std::runtime_error("unexpected end");
    char c = s[i];
    Json j;
    if (c == '[') {
      i++;
      j.kind = Json::ARR;
      ws();
      if (i < s.size() && s[i] == ']') { i++; return j; }
      while (true) {
        j.arr.push_back(parse());
        ws();
        if (i < s.size() && s[i] == ',') { i++; continue; }
        if (i < s.size() && s[i] == ']') { i++; break; }
        throw std::runtime_error("expected , or ] at " + std::to_string(i));
      }
      return j;
    }
    if (c == '"') {
      i++;
      std::string out;
      while (i < s.size() && s[i] != '"') {
        if (s[i] == '\\' && i + 1 < s.size()) {
          i++;
          out += s[i++];
        } else {
          out += s[i++];
        }
      }
      if (i >= s.size()) throw std::runtime_error("unterminated string");
      i++;
      j.kind = Json::STR;
      j.str = out;
      return j;
    }
    if (c == '-' || isdigit((unsigned char)c)) {
      size_t start = i;
      if (s[i] == '-') i++;
      while (i < s.size() && isdigit((unsigned char)s[i])) i++;
      j.kind = Json::NUM;
      j.num = std::stoll(s.substr(start, i - start));
      return j;
    }
    if (s.compare(i, 4, "true") == 0) { i += 4; j.kind = Json::NUM; j.num = 1; return j; }
    if (s.compare(i, 5, "false") == 0) { i += 5; j.kind = Json::NUM; j.num = 0; return j; }
    throw std::runtime_error("unsupported token at " + std::to_string(i));
  }
};

static std::vector<std::string> split(const std::string &s, char delim) {
  std::vector<std::string> out;
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) out.push_back(item);
  return out;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    std::fprintf(stderr,
        "usage: aether_vm <kernel.json|--> <in1,in2,...> [scale]\n"
        "prints the scaled integer result (same domain as core/vm.py)\n");
    return 2;
  }
  std::string ir_text;
  if (std::strcmp(argv[1], "--stdin") == 0) {
    std::ostringstream buf;
    buf << std::cin.rdbuf();
    ir_text = buf.str();
  } else {
    std::ifstream f(argv[1]);
    if (!f) { std::fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }
    std::ostringstream buf;
    buf << f.rdbuf();
    ir_text = buf.str();
  }

  // parse: {"ops":[["PUSH",5],...],"inputs":["x",...],"scale":N}
  // The restricted reader handles arrays/strings/ints; the object wrapper
  // is extracted key-by-key below (IR strings never contain brackets).
  std::vector<Op> prog;
  std::vector<std::string> inputs;
  long long scale = 1000000;
  {
    auto grab = [&](const std::string &key, std::string &out) -> bool {
      size_t k = ir_text.find("\"" + key + "\"");
      if (k == std::string::npos) return false;
      size_t colon = ir_text.find(':', k);
      size_t start = ir_text.find_first_of("[\"", colon + 1);
      if (start == std::string::npos) return false;
      if (ir_text[start] == '[') {
        int depth = 0;
        size_t j = start;
        for (; j < ir_text.size(); j++) {
          if (ir_text[j] == '[') depth++;
          else if (ir_text[j] == ']') { depth--; if (!depth) break; }
        }
        out = ir_text.substr(start, j - start + 1);
      } else if (ir_text[start] == '"') {
        size_t end = ir_text.find('"', start + 1);
        out = ir_text.substr(start, end - start + 1);
      } else {
        size_t end = start;
        while (end < ir_text.size() &&
               (isdigit((unsigned char)ir_text[end]) || ir_text[end] == '-'))
          end++;
        out = ir_text.substr(start, end - start);
      }
      return true;
    };

    std::string ops_s, inputs_s, scale_s;
    if (!grab("ops", ops_s)) {
      std::fprintf(stderr, "bad IR: no ops key\n");
      return 2;
    }
    if (grab("inputs", inputs_s) && !inputs_s.empty()) {
      Parser p2(inputs_s);
      Json in = p2.parse();
      for (auto &e : in.arr) inputs.push_back(e.str);
    }
    if (grab("scale", scale_s) && !scale_s.empty())
      scale = std::stoll(scale_s);

    Parser p3(ops_s);
    Json ops = p3.parse();
    for (auto &step : ops.arr) {
      if (step.kind != Json::ARR || step.arr.empty()) {
        std::fprintf(stderr, "bad op entry\n");
        return 2;
      }
      Op op;
      op.code = step.arr[0].str;
      if (step.arr.size() > 1) {
        if (step.arr[1].kind == Json::NUM) {
          op.has_num = true;
          op.num = step.arr[1].num;
        } else {
          op.arg = step.arr[1].str;
        }
      }
      prog.push_back(op);
    }
  }

  // inputs
  std::vector<std::string> raw = split(argv[2], ',');
  if (raw.size() != inputs.size()) {
    std::fprintf(stderr, "expected %zu inputs (%s), got %zu\n",
                 inputs.size(), argv[2], raw.size());
    return 2;
  }
  std::vector<long long> regs;
  for (auto &r : raw) {
    if (r.empty()) continue;
    double v = std::stod(r);
    regs.push_back(std::llround(v * (double)scale));
  }
  if (regs.size() != inputs.size()) {
    std::fprintf(stderr, "bad input list\n");
    return 2;
  }

  // stack machine — mirrors core/vm.py::run_plain semantics exactly
  std::vector<long long> st;
  auto pop = [&]() -> long long {
    if (st.empty()) throw std::runtime_error("stack underflow");
    long long v = st.back();
    st.pop_back();
    return v;
  };
  try {
    for (auto &op : prog) {
      if (op.code == "PUSH") {
        // constants were scaled at compile time (int(round(v*scale)))
        st.push_back(op.num);
      } else if (op.code == "LOAD") {
        long long v = 0;
        bool found = false;
        for (size_t k = 0; k < inputs.size(); k++) {
          if (inputs[k] == op.arg) { v = regs[k]; found = true; break; }
        }
        if (!found) throw std::runtime_error("unknown input " + op.arg);
        st.push_back(v);
      } else if (op.code == "ADD") {
        long long b = pop(), a = pop();
        st.push_back(a + b);
      } else if (op.code == "SUB") {
        long long b = pop(), a = pop();
        st.push_back(a - b);
      } else if (op.code == "MUL") {
        long long b = pop(), a = pop();
        // fixed-point: same half-to-even rounding as Python round()
        st.push_back(std::llrint((double)a * (double)b / (double)scale));
      } else if (op.code == "DIV") {
        long long b = pop(), a = pop();
        if (b == 0) throw std::runtime_error("division by zero");
        st.push_back(std::llrint((double)a * (double)scale / (double)b));
      } else if (op.code == "NEG") {
        st.push_back(-pop());
      } else {
        throw std::runtime_error("unknown op " + op.code);
      }
      if (st.size() > 64) throw std::runtime_error("stack overflow");
    }
  } catch (const std::exception &ex) {
    std::fprintf(stderr, "exec error: %s\n", ex.what());
    return 1;
  }
  if (st.size() != 1) {
    std::fprintf(stderr, "unbalanced kernel (depth %zu)\n", st.size());
    return 1;
  }
  std::printf("%lld\n", st.back());
  return 0;
}
