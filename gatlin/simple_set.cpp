/*
 * Simple Set
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */

#include "simple_set.h"
#include "utility.h"

#include <fstream>

/*
 * _f: file name
 * sl: builtin set
 */
SimpleSet::SimpleSet(const std::string &_f, const StringList sl) : f(_f) {
  _use_builtin = false;
  for (auto n : sl)
    builtin.insert(n);
  load(f);
}

void SimpleSet::load(const std::string &f) {
  std::ifstream input(f);
  if (!input.is_open()) {
    _use_builtin = true;
    return;
  }
  vars.clear();
  std::string line;
  while (std::getline(input, line)) {
    vars.insert(line);
  }
  input.close();
}

bool SimpleSet::exists(const std::string &str) {
  if (_use_builtin)
    return std::find(builtin.begin(), builtin.end(), str) != builtin.end();
  return vars.count(str) != 0;
}

bool SimpleSet::exists_ignore_dot_number(const std::string &str) {
  std::string _str = std::string(str);
  str_truncate_dot_number(_str);
  return exists(_str);
}

size_t SimpleSet::size() { return vars.size(); }

bool SimpleSet::use_builtin() { return _use_builtin; }
