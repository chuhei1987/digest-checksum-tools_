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

#include "tstring.h"

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

		definition() : optname(_T("")), value(0), kind(0), argstr(_T("")) {}
		definition(const TCHAR* zOptName, int nValue, int nKind, const TCHAR* zArgStr = NULL)
		{
			optname = zOptName == NULL ? _T("") : zOptName;
			value = nValue;
			kind = nKind;
			argstr = zArgStr == NULL ? _T("") : zArgStr;
		}

		static const definition& nullopt()
		{
			definition* nil = new definition;
			return *nil;
		}
		bool operator==(const definition& r)
		{
			if (value != r.value || kind != r.kind)
				return false;

			if (optname != _T(""))
				return false;

			if (argstr != _T(""))
				return false;

			return true;
		}

		bool operator!=(const definition& r) { return !(*this == r); }

		definition& operator=(const definition& v)
		{
			optname = v.optname;
			argstr = v.argstr;
			value = v.value;
			kind = v.kind;

			return *this;
		}
	};

private:
	str _zProgramName; //program name (program name only)

	std::vector<definition>::size_type _iOpt; //option index
	std::vector<definition> _optlist;

	const definition nullopt;

	msg_handler errs;

private:
	void parse_program_name(const str& optstr)
	{
		strs list = optstr.split(_T("\\")); //split path string by '\' delimiter
		_zProgramName = *list.rbegin();
		list.clear();
		if (!_zProgramName.is_null())
		{
			str::size_type pos = _zProgramName.length() - 1;
			while (pos != 0) //remove program extension, e.g. ".exe"
			{
				if (_zProgramName[pos] == '.')
				{
					_zProgramName = _zProgramName.substr(0, pos);
					break;
				}
				pos--;
			}
		}

		list.clear();

		//to lower case
		_zProgramName.to_lower();
	}

	bool match_definition_by_optname(str optstr, definition& opt, definition optdefs[])
	{
		definition* def;
		def = optdefs;

		while (*def != nullopt)
		{
			if (optstr.find(def->optname, 0) == 0)
			{
				opt = *def;
				return true;
			}
			def++;
		}
		return false;
	}

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
	}

	void parse_operand(definition& opt, const str& optstr)
	{
		opt.optname = optstr;
		opt.kind = operand;
		opt.value = 0;
		opt.argstr = _T("");
		_optlist.push_back(opt);
	}

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
						errs().format(_T("%s ==> -%c: attempts to take argument <%s> in compressed option format!"),
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
				errs().format(_T("%s ==> -%c: unknown option!"),
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
	}

	bool parse_long_option(definition& longopt, const str& optstr, bool& need_argument, definition optdefs[])
	{
		bool hasArg = false;
		str::size_type i = 0;
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
					errs().format(_T("%s ==> %s: cannot take any argument! ==> <%s>: illegal argument"),
						optstr.c_str(), longopt.optname.c_str(), optstr.substr(i + 1).c_str());
					return false;
				}
			}
			need_argument = longopt.kind == required_argument ? true : false;

			if (!need_argument)
				_optlist.push_back(longopt);

			return true;
		}

		errs().format(_T("%s ==> %s: unknown option!"),
			optstr.c_str(), optstr.c_str());
		return false;
	}
	void parse_option_argument(definition& opt, const str& optstr)
	{
		opt.argstr = optstr;
		_optlist.push_back(opt);
	}

	void parse_option_error()
	{
		if (!errs.is_empty()) //if has error
		{
			_optlist.push_back(definition(_T(""), '?', error,
				_T("some errors happened while parsing option(s)!")));

			errs(-1)
				.format(_T("%s: %d error(s) happen in option strings!"), 
					_zProgramName.c_str(), errs.count())
				.print();
		}
	}

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
	}

public:
	option(int argc, const TCHAR* argv[], option::definition optdefs[]) : errs(stderr)
	{
		//errs.set_outstream(stderr);
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
								errs().format(_T("%s ==> -%c: requires an argument!"),
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
									errs().format(_T("%s ==> %s: requires an argument!"),
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
	}
	~option() { _optlist.clear(); }

public:
	option& to_previous()
	{
		_iOpt--;
		return *this;
	}
	option& to_next()
	{
		_iOpt++;
		return *this;
	}
	option& to_begin()
	{
		_iOpt = 0;
		return *this;
	}
	option& to_end()
	{
		_iOpt = _optlist.size() - 1;
		return *this;
	}

	bool is_begin() { return _iOpt < 0; };
	bool is_end() { return _iOpt >= (int)_optlist.size(); }
 
	bool is_error() { return kind() == error; } //return true if current option ("?") kind is "error"
	bool has_error() { return errs.is_empty(); } //return true if has error
	bool is_empty() { return (_optlist.size() == 0); } //return true if no option found

	int value() { return _optlist[_iOpt].value; }
	int kind() { return _optlist[_iOpt].kind; }

	str& optname() { return _optlist[_iOpt].optname; }
	str& argstr() { return _optlist[_iOpt].argstr; }
};
