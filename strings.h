
/*
 text utilities - Some written in C++ for Windows platform.
 https://github.com/fshb/textutil/
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
#pragma once


#include <stdarg.h>
#include <stdio.h>
#include <tchar.h>
#include <vector>
#include <string>
#include <algorithm>

class TString : public std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR> >
{
private:
	typedef std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR> > _TStringBase;

public:
	typedef std::vector<TString> TStringList;

public:
	TString() : _TStringBase() {}
	TString(const TString& s) : _TStringBase((_TStringBase)s) {}
	TString(const _TStringBase& s) : _TStringBase(s) {}
	
	TString(const TString& s, size_type pos, size_type len = npos) : _TStringBase((_TStringBase)s, pos, len) {};
	TString(const _TStringBase& s, size_type pos, size_type len = npos) : _TStringBase(s, pos, len) {};
	T
	TString(const TCHAR* s) : _TStringBase(s) {}
	TString(const TCHAR* s, size_type n) : _TStringBase(s, n) {}
	String(size_type n, TCHAR c) : _TStringBase(n, c) {};

	template <class InputIterator> TString(InputIterator first, InputIterator last);


	template<class T> TString operator + (T& s)
	{
		_TStringBase ss = (_TStringBase)* this;
		ss += s;

		TString ts(ss);
		return ts;
	}

	template<class T> void operator = (T& s)
	{
		_TStringBase* this_base = (_TStringBase*)this;
		*this_base = s;
	}

	template<class T> void operator += (T& s)
	{
		_TStringBase* this_base = (_TStringBase*)this;
		*this_base += s;
	}

	template<class T> TString& operator << (T& s)
	{
		*this += s;
		return *this;
	}

	template<class T> bool operator == (T& s)
	{
		_TStringBase* this_base = (_TStringBase*)this;
		return (*this_base == s);
	}

	template<class T> bool operator != (T& s)
	{
		_TStringBase* this_base = (_TStringBase*)this;
		return (*this_base != s);
	}

	TString substr(size_type pos = 0, size_type len = npos) const
	{
		TString s(_TStringBase::substr(pos, len));
		return s;
	}

	TString& to_lower()
	{
		std::transform(begin(), end(), begin(), tolower);
		return *this;
	}
	TString& to_upper()
	{
		std::transform(begin(), end(), begin(), toupper);
		return *this;
	}

	void format(const TCHAR* fmt, va_list ap)
	{
		size_t sz = 1 + _vsctprintf(fmt, ap);
		TCHAR* buf = new TCHAR[sz];
		_vsntprintf_s(buf, sz, sz, fmt, ap);
		*this = buf;
		delete[] buf;
	}
	void format(const TCHAR* fmt, ...)
	{
		va_list ap;
		va_start(ap, fmt);
		format(fmt, ap);
		va_end(ap);
	}
	template<class T> TString delimiter(T& zDelim)
	{
		size_t pos = find(zDelim);
		TString s = substr(0, pos);
		return s;
	}
	size_t find(const TString& s, const size_t pos = 0)
	{
		return _TStringBase::find((_TStringBase)s, pos);
	}
	TString& replace_with(const TCHAR* zFrom, const TCHAR* zTo)
	{
		TString from = zFrom;
		TString to = zTo;

		size_t pos;
		for (pos = 0; pos != npos; pos += to.length())
		{
			pos = find(from, pos);
			if (pos != npos)
				replace(pos, from.length(), to);
			else
				break;
		}
		return *this;
	}
};

typedef TString::TStringList str_list;
typedef TString str;

class message_handler
{
private:
	struct message_t
	{
		int priority;
		bool suppress;
		str message;
		message_t() : priority(0), suppress(false) {}
	};
	std::vector<message_t> _msgs;

	FILE* _out_stream;

	str _delimiter;

public:
	message_handler() : _out_stream(stdout), _delimiter(_T("\n")) {}
	message_handler(FILE* f) : _out_stream(f), _delimiter(_T("\n")) {}

	~message_handler()
	{
		_msgs.clear();
	}

	void set_outstream(FILE* outstream)
	{
		_out_stream = outstream;
	}
	message_handler& operator()(int priority = 0, bool suppress = false)
	{
		message_t message;
		message.priority = priority;
		message.suppress = suppress;
		_msgs.push_back(message);
		return *this;
	}

	template<class T> message_handler& operator << (T& message)
	{
		size_t i = _msgs.size() - 1;
		_msgs[i].message << message;
		return *this;
	}

	size_t count()
	{
		return _msgs.size();
	}

	bool is_empty()
	{
		return (count() == 0);
	}
	void set_delimiter(str delim)
	{
		_delimiter = delim;
	}

	message_handler& format(const TCHAR* fmt, ...)
	{
		va_list ap;
		va_start(ap, fmt);
		size_t i = _msgs.size() - 1;
		_msgs[i].message.format(fmt, ap);
		va_end(ap);
		return *this;
	}

	void print()
	{
		struct
		{
			bool operator()(message_t& msg1, message_t& msg2)
			{
				return (msg1.priority < msg2.priority);
			}
		} _ascending_order;

		std::sort(_msgs.begin(), _msgs.end(), _ascending_order);

		struct PRINT_T
		{
		private:
			FILE* _out;
		public:
			PRINT_T(FILE* f) : _out(f) {}
			void operator()(message_t& message)
			{
				if (!message.suppress)
					_ftprintf(_out, _T("%s%s"), message.message.c_str(), _delimiter.c_str());
			}
		} _print_msg(_out_stream);

		std::for_each(_msgs.begin(), _msgs.end(), _print_msg);
	}
};
