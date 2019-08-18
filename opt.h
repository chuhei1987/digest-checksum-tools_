/*
 Option parser - An embedded program option parser (POSIX/GNU style) written in C++ for Windows platform.
 https://github.com/fshb/optparser/
 Copyright (c) 2019 Sun Hongbo (Felix)

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this Software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
*/

#ifdef USAGE //usage

#include "opt.h" //include optparser header
void Error() { /*TODO: Code...*/ }
void Usage() { /*TODO: Code...*/ }
void Verbose() { /*TODO: Code...*/ }
void Check(str argstr) { /*TODO: Code...*/ }
void SetStatus(str argstr) { /*TODO: Code...*/ }
void GetInput(str input) { /*TODO: Code...*/ }
void GetOutput(str output) { /*TODO: Code...*/ }

int main(int argc, TCHAR* argv[])
{
	option::definition optdefs[] = {
		{_T("--input"), 'i', option::required_argument},
		{_T("--output"), 'o', option::required_argument},
		{_T("--help"), 'h', option::no_argument},
		{_T("--verbose"), 'v', option::no_argument},
		{_T("--check"), 'c', option::optional_argument},
		{_T("--status"), 1234, option::optional_argument},
		option::definition::nullopt() };

	option opt(argc, argv, optdefs);

	while (!opt.is_end())
	{
		switch (opt.value())
		{
		case 'i':
			GetInput(opt.optname());
			break;

		case 'o':
			GetOutput(opt.optname());
			break;

		case 'c':
			Check(opt.argstr());
			break;

		case 1234:
			SetStatus(opt.argstr());
			break;

		case '?': //will generate a "?" as an error indicator
			if (opt.kind() == option::error) //error happened
			{
				Error();
				return 0;
			}
		case 'h':
			Usage();
			return 0;

		case 'v':
			Verbose();
			return 0;

		default:
			break;
		}

		opt.to_next(); //to next option
	}

	return 0;
}

#endif
#pragma once
#include <stdarg.h>
#include <stdio.h>
#include <tchar.h>
#include <vector>
#include <string>
#include <algorithm>

typedef std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR> > str;

class option
{
public:
	enum : int
	{
		error = -1, //illegal option usage or unknown options found.
		no_argument = 0,
		required_argument,
		optional_argument,
		operand = 999
	};

	struct definition
	{
		str optname;
		int value;
		int kind;
		str argstr;

		definition() : optname(_T("")), value(0), kind(0), argstr(_T("")) {};
		definition(const TCHAR* zOptName, int nValue, int nKind, const TCHAR* zArgStr = NULL)
		{
			optname = zOptName == NULL ? _T("") : zOptName;
			value = nValue;
			kind = nKind;
			argstr = zArgStr == NULL ? _T("") : zArgStr;
		};

		static const definition& nullopt()
		{
			definition* nil = new definition;
			return *nil;
		};
		bool operator==(const definition& r)
		{
			if (value != r.value || kind != r.kind)
				return false;

			if (optname != _T(""))
				return false;

			if (argstr != _T(""))
				return false;

			return true;
		};

		bool operator!=(const definition& r)
		{
			return !(*this == r);
		};

		definition& operator=(const definition& v)
		{
			optname = v.optname;
			argstr = v.argstr;
			value = v.value;
			kind = v.kind;

			return *this;
		};
	};

private:
	str _zProgramName; //program name (program name only)

	int _nErrCount; //error count

	int _iOpt; //option index
	std::vector<definition> _optlist;

	const definition nullopt;

private:
	void parse_program_name(const str& optstr)
	{
		int i = optstr.length() - 1;
		bool b = false;
		while (i != 0) //remove directory path in the name
		{
			if (optstr[i] == '\\')
			{
				_zProgramName = optstr.substr(i + 1);
				b = true;
				break;
			}
			i--;
		}

		if (!b)
			_zProgramName = optstr;

		i = _zProgramName.length() - 1;
		b = false;
		while (i != 0) //remove extension, e.g. ".exe"
		{
			if (_zProgramName[i] == '.')
			{
				_zProgramName = _zProgramName.substr(0, i);
				break;
			}
			i--;
		}
		//to lower case
		std::transform(_zProgramName.begin(), _zProgramName.end(), _zProgramName.begin(), ::tolower);
	};

	bool match_definition_by_optname(const str& optstr, definition& opt, definition optdefs[])
	{
		definition* def;
		def = optdefs;
		while (*def != nullopt)
		{
			if (optstr == def->optname)
			{
				opt = *def;
				return true;
			}
			def++;
		}
		return false;
	};

	bool match_definition_by_value(int value, definition& opt, definition optdefs[])
	{
		definition* def;
		def = optdefs;
		while (*def != nullopt)
		{
			if (value == def->value)
			{
				opt = *def;
				return true;
			}
			def++;
		}
		return false;
	};

	void parse_operand(definition& opt, const str& optstr)
	{
		opt.optname = optstr;
		opt.kind = operand;
		opt.value = 0;
		opt.argstr = _T("");
		_optlist.push_back(opt);
	};

	bool parse_short_options(definition& shortopt, str& zValues, bool& need_argument, definition optdefs[])
	{
		bool haserr = false;
		size_t len = zValues.length();
		need_argument = false;

		size_t i = 1;
		for (i = 1; i < len; i++)
		{
			if (match_definition_by_value((int)zValues[i], shortopt, optdefs))
			{
				if (shortopt.kind == required_argument || shortopt.kind == optional_argument)
				{
					if (i != 1)
					{
						err(_T("%s ==> -%c: attempts to take argument <%s> in compressed option format!\n"),
							zValues.c_str(), zValues[i], zValues.substr(i + 1).c_str());
						haserr = true;
					}

					if (len == 2 && shortopt.kind == required_argument)
					{
						need_argument = true;
						return true;
					}

					if (len > 2 && !haserr)
					{
						parse_option_argument(shortopt, zValues.substr(i + 1));
						return true;
					}
				}
			}
			else
			{
				err(_T("%s ==> -%c: unknown option!\n"),
					zValues.c_str(), zValues[i]);
				haserr = true;
			}
		} //END for (size_t i = 1; i < len; i++)

		for (i = 1; i < len; i++)
		{
			if (match_definition_by_value(zValues[i], shortopt, optdefs) && !haserr/*no error*/)
			{
				_optlist.push_back(shortopt);
			}
		}

		return !haserr;
	};

	bool parse_long_option(definition& longopt, const str& optstr, bool& need_argument, definition optdefs[])
	{
		bool hasArg = false;
		int i = 0;
		while (optstr[i] != '\0')
		{
			if (optstr[i] == '=')
			{
				hasArg = true;
				break;
			}
			i++;
		}

		if (match_definition_by_optname(optstr, longopt, optdefs))
		{
			if (hasArg)
			{
				if (longopt.kind == required_argument || longopt.kind == optional_argument)
				{
					parse_option_argument(longopt, optstr.substr(i + 1));
					
					return true;
				}
				else if (longopt.kind == no_argument)
				{
					err(_T("%s ==> %s: cannot take any argument! ==> <%s>: illegal argument\n"),
						optstr.c_str(), longopt.optname.c_str(), optstr.substr(i + 1).c_str());
					return false;
				}
			}
			need_argument = longopt.kind == required_argument ? true : false;

			if (!need_argument)
				_optlist.push_back(longopt);

			return true;
		}

		err(_T("%s ==> %s: unknown option!\n"),
			optstr.c_str(), optstr.c_str());
		return false;
	};
	void parse_option_argument(definition& opt, const str& optstr)
	{
		opt.argstr = optstr;
		_optlist.push_back(opt);
	};

	void parse_option_error()
	{
		if (_nErrCount) //if has error
		{
			_optlist.push_back(definition(_T(""), '?', error,
				_T("some errors happened while parsing option(s)!")));
		}
	};
	void err(const TCHAR* fmt, ...)
	{
		if (_nErrCount == 0)
			_ftprintf(stderr, _T("%s: error(s) in option(s):\n"), _zProgramName.c_str());

		va_list ap;
		va_start(ap, fmt);
		_vftprintf(stderr, fmt, ap);
		va_end(ap);
		_nErrCount++;
	};

	//adjust parsed options' order by kind in following rule:
	//error(unknown/illegal) -> no_argument -> required_argument -> optional_argument -> operand
	void reorder_options()
	{
		struct
		{
			bool operator()(definition& a, definition& b) const
			{
				return a.kind < b.kind;
			}
		} ascend_order_by_kind;
		std::sort(_optlist.begin(), _optlist.end(), ascend_order_by_kind);
	};

public:
	option(int argc, const TCHAR* argv[], option::definition optdefs[])
	{
		_nErrCount = 0; //initialize error count
		int i = 0;
		size_t len = 0;
		str argstr;
		bool is_operand_only = false;
		bool need_argument = false;
		definition opt;

		argstr = argv[0];
		parse_program_name(argstr);
		for (i = 1; i < argc; i++)
		{
			argstr = argv[i];
			len = argstr.length();
			need_argument = false;
			if (!is_operand_only && argstr[0] == '-' && argstr[1] != '\0'/*"-" option*/)
			{
				if (argstr[1] != '-')
				{
					if (parse_short_options(opt, argstr, need_argument, optdefs))
					{
						if (need_argument)
						{
							if (++i >= argc)
							{
								err(_T("%s ==> -%c: requires an argument!"),
									argstr.c_str(), argstr[len - 1]);
							}
							else
							{
								argstr = argv[i];
								parse_option_argument(opt, argstr);
							}
						}
					} //END if (parse_short_option(opt, argstr, optdefs))
				}//END else if(argstr[1] != '-')
				else
				{
					if (argstr[2] == '\0') //"--" delimeter
						is_operand_only = true;
					else
					{
						if (parse_long_option(opt, argstr, need_argument, optdefs))
						{
							if (need_argument)
							{
								if (++i >= argc)
								{
									err(_T("%s ==> %s: requires an argument!"),
										argstr.c_str(), opt.optname.c_str());
								}
								else
								{
									argstr = argv[i];
									parse_option_argument(opt, argstr);
								}
							} //END if (need_argument)
						} //END if (parse_long_option(opt, argstr, need_argument, optdefs))
					}//END else
				}//END else
			}//END if (!is_operand_only && argstr[0] == '-')
			else
				parse_operand(opt, argstr);
		} //END for (i = 1; i < argc; i++)
		_iOpt = 0;
		parse_option_error();
		reorder_options();
	};
	~option() { _optlist.clear(); };

public:
	option& to_previous()
	{
		_iOpt--;
		return *this;
	};
	option& to_next()
	{
		_iOpt++;
		return *this;
	};
	option& to_begin()
	{
		_iOpt = 0;
		return *this;
	};
	option& to_end()
	{
		_iOpt = _optlist.size() - 1;
		return *this;
	};

	bool is_begin() { return _iOpt < 0; };
	bool is_end() { return _iOpt >= (int)_optlist.size(); };
 
	bool is_error() { return kind() == error; }; //return true if current option ("?") kind is "error"
	bool has_error() { return _nErrCount > 0; }; //return true if has error

	int value() { return _optlist[_iOpt].value; };
	int kind() { return _optlist[_iOpt].kind; };

	str& optname() { return _optlist[_iOpt].optname; };
	str& argstr() { return _optlist[_iOpt].argstr; };
};

#ifdef TEST
//test code, put below code to an individule .cpp file

#include "opt.h"
#include <windows.h>

#include <stdlib.h>

str KSTR(int kind)
{
	str s;
	switch (kind)
	{
	case option::error:
		s = _T("error");
		break;
	case option::operand:
		s = _T("operand");
		break;
	case option::no_argument:
		s = _T("no_argument");
		break;
	case option::required_argument:
		s = _T("required_argument");
		break;
	case option::optional_argument:
		s = _T("optional_argument");
		break;
	default:
		s = _T("");
		break;
	}
	return s;
}
int main()
{
	option::definition optdefs[] = {
		{_T("--input"), 'i', option::required_argument},
		{_T("--output"), 'o', option::required_argument},
		{_T("--help"), 'h', option::no_argument},
		{_T("--verbose"), 'v', option::no_argument},
		{_T("--check"), 'c', option::optional_argument},
		{_T("--status"), 1234, option::optional_argument},
		option::definition::nullopt() };
	const TCHAR* argv[] =
	{
		_T(".\\main.exe"),
		_T("-iabc"),
		_T("-vh"),
		_T("--output=abc"),
		_T("-o"),
		_T("-"),
		_T("-c"),
		_T("--output"),
		_T("--help"),
		_T("-cabc"),
		_T("--help=abc"),
		_T("-?ch"),
		_T("-hcsABc"),
		//_T("--input")
		_T("--"),
		_T("-iabc"),
		_T("-"),
		_T("--input")
		//_T("-i")
	};

	int argc = _countof(argv);

	_tprintf(_T("TEST: main.exe"));

	for (int i = 1; i < argc; i++)
	{
		_tprintf(_T(" %s"), argv[i]);
	}
	_tprintf(_T("\n\n"));

	option opt(argc, argv, optdefs);
	_tprintf(_T("\n\nParsing result (reordered):\n"));
	while (!opt.is_end())
	{
		_tprintf(_T("Option: %10s, Value: %4c, Kind: %20s, Arg: %s\n"),
			opt.optname().c_str(),
			opt.value(),
			KSTR(opt.kind()).c_str(),
			opt.argstr().c_str());
		opt.to_next();
	}

	system("pause");
	return 0;
}

#endif