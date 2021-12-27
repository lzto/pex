/*
 * Simple Set, either use builtin or load from file
 * 2018 Tong Zhang<t.zhang2@partner.samsung.com>
 */

#ifndef _SIMPLE_SET_
#define _SIMPLE_SET_

#include "commontypes.h"

#include <iterator>

using namespace std;

class SimpleSet {
private:
  void load(const string &);
  std::string f;
  StringSet builtin;
  bool _use_builtin;
  StringSet vars;

public:
  SimpleSet(const string &, const StringList &);
  SimpleSet(const StringRef _f, const StringList &sl)
      : SimpleSet(std::string(_f), sl) {}
  ~SimpleSet(){};
  bool use_builtin() { return _use_builtin; }
  bool exists(const std::string &);
  bool exists(const StringRef str) { return exists(std::string(str)); }
  bool exists_ignore_dot_number(const std::string &);
  size_t size() { return vars.size(); };

  /*
   * iterator stuff
   */
  using iterator = StringSet::iterator;
  using const_iterator = StringSet::const_iterator;

  iterator begin() {
    if (_use_builtin)
      return builtin.begin();
    return vars.begin();
  }

  iterator end() {
    if (_use_builtin)
      return builtin.end();
    return vars.end();
  }
};

#endif //_SIMPLE_SET_
